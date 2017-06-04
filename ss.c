/*
 * This file is part of Samsung-RIL.
 *
 * Copyright (C) 2013 Paul Kocialkowski <contact@paulk.fr>
 * Copyright (C) 2017 Wolfgang Wiedmeyer <wolfgit@wiedmeyer.de>
 *
 * Samsung-RIL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Samsung-RIL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Samsung-RIL.  If not, see <http://www.gnu.org/licenses/>.
 */

#define LOG_TAG "RIL-SS"
#include <utils/Log.h>

#include <samsung-ril.h>
#include <utils.h>

int ipc_ss_ussd_callback(struct ipc_message *message)
{
	struct ipc_gen_phone_res_data *data;
	int rc;

	if (message == NULL || message->data == NULL || message->size < sizeof(struct ipc_gen_phone_res_data))
		return -1;

	data = (struct ipc_gen_phone_res_data *) message->data;

	rc = ipc_gen_phone_res_check(data);
	if (rc < 0) {
		RIL_LOGE("There was an error, aborting USSD request");
		goto error;
	}

	RIL_LOGD("USSD callback code 0x%04x", data->code);

	// catch error codes if no IPC_SS_USSD notification is sent
	if ((data->code & 0xff) == 0x32 || (data->code & 0xff) == 0x24)
		goto error;

	ril_request_complete(ipc_fmt_request_token(message->aseq), RIL_E_SUCCESS, NULL, 0);
	goto complete;

error:
	ril_request_data_free(RIL_REQUEST_SEND_USSD);
	ril_request_complete(ipc_fmt_request_token(message->aseq), RIL_E_GENERIC_FAILURE, NULL, 0);

complete:
	return 0;
}

int ril_request_send_ussd(void *data, size_t size, RIL_Token token)
{
	char *data_enc = NULL;
	int data_enc_len = 0;
	char *message = NULL;
	struct ipc_ss_ussd_header *ussd = NULL;
	int message_size = 0xc0;
	void *ussd_state_data;
	size_t ussd_state_size;
	unsigned char ussd_state = 0;
	struct ril_request *request;
	int rc;

	if (data == NULL || size < sizeof(char *))
		goto error;

	rc = ril_radio_state_check(RADIO_STATE_SIM_NOT_READY);
	if (rc < 0)
		return RIL_REQUEST_UNHANDLED;

	request = ril_request_find_request_status(RIL_REQUEST_SEND_USSD, RIL_REQUEST_HANDLED);
	if (request != NULL) {
		return RIL_REQUEST_UNHANDLED;
	}

	ussd_state_size = ril_request_data_size_get(RIL_REQUEST_SEND_USSD);
	ussd_state_data = ril_request_data_get(RIL_REQUEST_SEND_USSD);

	if (ussd_state_data != NULL && ussd_state_size > 0) {
		ussd_state = *((unsigned char *) ussd_state_data);
		free(ussd_state_data);
	}

	switch (ussd_state) {
		case 0:
		case IPC_SS_USSD_NO_ACTION_REQUIRE:
		case IPC_SS_USSD_TERMINATED_BY_NET:
		case IPC_SS_USSD_OTHER_CLIENT:
		case IPC_SS_USSD_NOT_SUPPORT:
		case IPC_SS_USSD_TIME_OUT:
			RIL_LOGD("USSD Tx encoding is GSM7");

			data_enc_len = ascii2gsm7_ussd(data, (unsigned char**)&data_enc, (int) size);
			if (data_enc_len > message_size) {
				RIL_LOGE("USSD message size is too long, aborting");
				goto error;
			}

			message = malloc(message_size);
			memset(message, 0, message_size);

			ussd = (struct ipc_ss_ussd_header *) message;
			ussd->state = IPC_SS_USSD_NO_ACTION_REQUIRE;
			ussd->dcs = 0x0f; // GSM7 in that case
			ussd->length = data_enc_len;

			memcpy((void *) (message + sizeof(struct ipc_ss_ussd_header)), data_enc, data_enc_len);

			break;
		case IPC_SS_USSD_ACTION_REQUIRE:
		default:
			RIL_LOGD("USSD Tx encoding is ASCII");

			data_enc_len = asprintf(&data_enc, "%s", (char*)data);

			if (data_enc_len > message_size) {
				RIL_LOGE("USSD message size is too long, aborting");
				goto error;
			}

			message = malloc(message_size);
			memset(message, 0, message_size);

			ussd = (struct ipc_ss_ussd_header *) message;
			ussd->state = IPC_SS_USSD_ACTION_REQUIRE;
			ussd->dcs = 0x0f; // ASCII in that case
			ussd->length = data_enc_len;

			memcpy((void *) (message + sizeof(struct ipc_ss_ussd_header)), data_enc, data_enc_len);

			break;
	}

	if (message == NULL) {
		RIL_LOGE("USSD message is empty, aborting");
		goto error;
	}

	ipc_gen_phone_res_expect_callback(ipc_fmt_request_seq(token), IPC_SS_USSD,
		ipc_ss_ussd_callback);

	rc = ipc_fmt_send(ipc_fmt_request_seq(token), IPC_SS_USSD, IPC_TYPE_EXEC, (void *) message, message_size);
	if (rc < 0)
		goto error;

	rc = RIL_REQUEST_HANDLED;
	goto complete;

error:
	ril_request_complete(token, RIL_E_GENERIC_FAILURE, NULL, 0);
	rc = RIL_REQUEST_COMPLETED;

complete:
	if (data_enc != NULL && data_enc_len > 0)
		free(data_enc);

	return rc;
}

int ril_request_cancel_ussd(void *data, size_t size, RIL_Token token)
{
	struct ipc_ss_ussd_header ussd;
	int rc;

	rc = ril_radio_state_check(RADIO_STATE_SIM_NOT_READY);
	if (rc < 0)
		return RIL_REQUEST_UNHANDLED;

	memset(&ussd, 0, sizeof(ussd));

	ussd.state = IPC_SS_USSD_TERMINATED_BY_NET;

	rc = ipc_gen_phone_res_expect_complete(ipc_fmt_request_seq(token), IPC_SS_USSD);
	if (rc < 0)
		goto error;

	rc = ipc_fmt_send(ipc_fmt_request_seq(token), IPC_SS_USSD, IPC_TYPE_EXEC, (void *) &ussd, sizeof(ussd));
	if (rc < 0)
		goto error;

	rc = RIL_REQUEST_HANDLED;
	goto complete;

error:
	ril_request_complete(token, RIL_E_GENERIC_FAILURE, NULL, 0);
	rc = RIL_REQUEST_COMPLETED;

complete:
	return rc;
}

int ipc2ril_ussd_state(struct ipc_ss_ussd_header *ussd, char *message[2])
{
	if (ussd == NULL || message == NULL)
		return -1;

	switch (ussd->state) {
		case IPC_SS_USSD_NO_ACTION_REQUIRE:
			asprintf(&message[0], "%d", 0);
			break;
		case IPC_SS_USSD_ACTION_REQUIRE:
			asprintf(&message[0], "%d", 1);
			break;
		case IPC_SS_USSD_TERMINATED_BY_NET:
			asprintf(&message[0], "%d", 2);
			break;
		case IPC_SS_USSD_OTHER_CLIENT:
			asprintf(&message[0], "%d", 3);
			break;
		case IPC_SS_USSD_NOT_SUPPORT:
			asprintf(&message[0], "%d", 4);
			break;
		case IPC_SS_USSD_TIME_OUT:
			asprintf(&message[0], "%d", 5);
			break;
	}

	return 0;
}

int ipc2ril_ussd_encoding(int data_encoding)
{
	switch (data_encoding >> 4) {
	case 0x00:
	case 0x02:
	case 0x03:
		return USSD_ENCODING_GSM7;
	case 0x01:
		if (data_encoding == 0x10)
			return USSD_ENCODING_GSM7;
		if (data_encoding == 0x11)
			return USSD_ENCODING_UCS2;
		break;
	case 0x04:
	case 0x05:
	case 0x06:
	case 0x07:
		if (data_encoding & 0x20)
			return USSD_ENCODING_UNKNOWN;
		if (((data_encoding >> 2) & 3) == 0)
			return USSD_ENCODING_GSM7;
		if (((data_encoding >> 2) & 3) == 2)
			return USSD_ENCODING_UCS2;
		break;
	case 0xF:
		if (!(data_encoding & 4))
			return USSD_ENCODING_GSM7;
		break;
	}

	return USSD_ENCODING_UNKNOWN;
}

int ipc_ss_ussd(struct ipc_message *message)
{
	char *data_dec = NULL;
	int data_dec_len = 0;
	char *ussd_message[2];
	int ussd_encoding;
	struct ipc_ss_ussd_header *ussd = NULL;
	unsigned char state;
	int rc;

	if (message == NULL || message->data == NULL || message->size < sizeof(struct ipc_ss_ussd_header))
		goto error;

	memset(ussd_message, 0, sizeof(ussd_message));

	ussd = (struct ipc_ss_ussd_header *) message->data;

	rc = ipc2ril_ussd_state(ussd, ussd_message);
	if (rc < 0)
		goto error;

	ril_request_data_set_uniq(RIL_REQUEST_SEND_USSD, (void *) &ussd->state, sizeof(unsigned char));

	if (ussd->length > 0 && message->size > 0 && message->data != NULL) {
		ussd_encoding = ipc2ril_ussd_encoding(ussd->dcs);
		switch (ussd_encoding) {
			case USSD_ENCODING_GSM7:
				RIL_LOGD("USSD Rx encoding is GSM7");

				data_dec_len = gsm72ascii((unsigned char *) message->data
							  + sizeof(struct ipc_ss_ussd_header), &data_dec, message->size - sizeof(struct ipc_ss_ussd_header));
				asprintf(&ussd_message[1], "%s", data_dec);
				ussd_message[1][data_dec_len] = '\0';
				break;
			case USSD_ENCODING_UCS2:
				RIL_LOGD("USSD Rx encoding %x is UCS2", ussd->dcs);

				data_dec_len = message->size - sizeof(struct ipc_ss_ussd_header);
				ussd_message[1] = malloc(data_dec_len * 4 + 1);

				int i, result = 0;
				char *ucs2 = (char*)message->data + sizeof(struct ipc_ss_ussd_header);
				for (i = 0; i < data_dec_len; i += 2) {
					int c = (ucs2[i] << 8) | ucs2[1 + i];
					result += utf8_write(ussd_message[1], result, c);
				}
				ussd_message[1][result] = '\0';
				break;
			default:
				RIL_LOGD("USSD Rx encoding %x is unknown, assuming ASCII",
					ussd->dcs);

				data_dec_len = message->size - sizeof(struct ipc_ss_ussd_header);
				asprintf(&ussd_message[1], "%s", (unsigned char *) message->data + sizeof(struct ipc_ss_ussd_header));
				ussd_message[1][data_dec_len] = '\0';
				break;
		}
	}

	ril_request_unsolicited(RIL_UNSOL_ON_USSD, ussd_message, sizeof(ussd_message));
	goto complete;

error:
	ril_request_complete(ipc_fmt_request_token(message->aseq), RIL_E_GENERIC_FAILURE, NULL, 0);

complete:
	return 0;
}
