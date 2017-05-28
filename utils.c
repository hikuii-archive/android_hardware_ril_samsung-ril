/*
 * This file is part of Samsung-RIL.
 *
 * Copyright (C) 2010-2011 Joerie de Gram <j.de.gram@gmail.com>
 * Copyright (C) 2011-2014 Paul Kocialkowski <contact@paulk.fr>
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

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/eventfd.h>

#define LOG_TAG "RIL"
#include <utils/Log.h>

#include <samsung-ril.h>
#include <utils.h>

struct list_head *list_head_alloc(struct list_head *prev, struct list_head *next,
	const void *data)
{
	struct list_head *list;

	list = calloc(1, sizeof(struct list_head));
	list->data = data;
	list->prev = prev;
	list->next = next;

	if (prev != NULL)
		prev->next = list;
	if (next != NULL)
		next->prev = list;

	return list;
}

void list_head_free(struct list_head *list)
{
	if (list == NULL)
		return;

	if (list->next != NULL)
		list->next->prev = list->prev;
	if (list->prev != NULL)
		list->prev->next = list->next;

	memset(list, 0, sizeof(struct list_head));
	free(list);
}

/*
 * Converts GSM7 (8 bits) data to ASCII (7 bits)
 */
int gsm72ascii(unsigned char *data, char **data_dec, int length)
{
	int t, u, d, o = 0;
	int i;

	int dec_length;
	char *dec;

	dec_length = ((length * 8) - ((length * 8) % 7) ) / 7;
	dec = malloc(dec_length);

	memset(dec, 0, dec_length);

	for (i = 0 ; i < length ; i++)
	{
		d = 7 - i % 7;
		if (d == 7 && i != 0)
			o++;

		t = (data[i] - (((data[i] >> d) & 0xff) << d));
		u = (data[i] >> d) & 0xff;

		dec[i+o]+=t << (i + o) % 8;

		if (u)
			dec[i+1+o]+=u;
	}

	*data_dec = dec;

	return dec_length;
}

/*
 * Converts ASCII (7 bits) data to GSM7 (8 bits)
 */
int ascii2gsm7_ussd(char *data, unsigned char **data_enc, int length)
{
	int d_off, d_pos, a_off, a_pos = 0;
	int i;

	int enc_length;
	unsigned char *enc;

	enc_length = ((length * 7) - (length * 7) % 8) / 8;
	enc_length += (length * 7) % 8 > 0 ? 1 : 0;

	//FIXME: why does samsung does that?
	enc_length++;

	enc = malloc(enc_length);
	memset(enc, 0, enc_length);

	for (i = 0 ; i < length ; i++)
	{
		// offset from the right of data to keep
		d_off = i % 8;

		// position of the data we keep
		d_pos = ((i * 7) - (i * 7) % 8) / 8;
		d_pos += (i * 7) % 8 > 0 ? 1 : 0;

		// adding the data with correct offset
		enc[d_pos] |= data[i] >> d_off;

		// numbers of bits to omit to get data to add another place
		a_off = 8 - d_off;
		// position (on the encoded feed) of the data to add
		a_pos = d_pos - 1;

		// adding the data to add at the correct position
		enc[a_pos] |= data[i] << a_off;
	}

	*data_enc = enc;

	//FIXME: what is going on here?
	enc[enc_length - 2] |= 0x30;
	enc[enc_length - 1] = 0x02;

	return enc_length;
}

/* writes the utf8 character encoded in v
 * to the buffer utf8 at the specified offset
 */
int utf8_write(char *utf8, int offset, int v)
{

	int result;

	if (v < 0x80) {
		result = 1;
		if (utf8)
			utf8[offset] = (char)v;
	} else if (v < 0x800) {
		result = 2;
		if (utf8) {
			utf8[offset + 0] = (char)(0xc0 | (v >> 6));
			utf8[offset + 1] = (char)(0x80 | (v & 0x3f));
		}
	} else if (v < 0x10000) {
		result = 3;
		if (utf8) {
			utf8[offset + 0] = (char)(0xe0 | (v >> 12));
			utf8[offset + 1] = (char)(0x80 | ((v >> 6) & 0x3f));
			utf8[offset + 2] = (char)(0x80 | (v & 0x3f));
		}
	} else {
		result = 4;
		if (utf8) {
			utf8[offset + 0] = (char)(0xf0 | ((v >> 18) & 0x7));
			utf8[offset + 1] = (char)(0x80 | ((v >> 12) & 0x3f));
			utf8[offset + 2] = (char)(0x80 | ((v >> 6) & 0x3f));
			utf8[offset + 3] = (char)(0x80 | (v & 0x3f));
		}
	}
	return result;
}

sms_coding_scheme sms_get_coding_scheme(int data_encoding)
{
	switch (data_encoding >> 4) {
	case 0x00:
	case 0x02:
	case 0x03:
		return SMS_CODING_SCHEME_GSM7;
	case 0x01:
		if (data_encoding == 0x10)
			return SMS_CODING_SCHEME_GSM7;
		if (data_encoding == 0x11)
			return SMS_CODING_SCHEME_UCS2;
		break;
	case 0x04:
	case 0x05:
	case 0x06:
	case 0x07:
		if (data_encoding & 0x20)
			return SMS_CODING_SCHEME_UNKNOWN;
		if (((data_encoding >> 2) & 3) == 0)
			return SMS_CODING_SCHEME_GSM7;
		if (((data_encoding >> 2) & 3) == 2)
			return SMS_CODING_SCHEME_UCS2;
		break;
	case 0xF:
		if (!(data_encoding & 4))
			return SMS_CODING_SCHEME_GSM7;
		break;
	}
	return SMS_CODING_SCHEME_UNKNOWN;
}

int data_dump(const void *data, size_t size)
{
	unsigned int cols = 8;
	unsigned int cols_count = 2;
	int spacer;
	char string[81];
	size_t length;
	char *print;
	unsigned char *p;
	unsigned int offset;
	unsigned int rollback;
	unsigned int i, j, k;
	int rc;

	if (data == NULL || size == 0)
		return -1;

	// spacer = string length - offset print length - data print length - ascii print length
	spacer = (sizeof(string) - 1) - 6 - (3 * cols * cols_count - 1 + (cols_count - 1)) - (cols * cols_count + cols_count - 1);

	// Need 3 spacers
	spacer /= 3;

	if (spacer <= 0)
		return -1;

	p = (unsigned char *) data;
	offset = 0;

	while (offset < size) {
		rollback = 0;

		print = (char *) &string;
		length = sizeof(string);

		// Offset print

		rc = snprintf(print, length, "[%04x]", offset);
		print += rc;
		length -= rc;

		// Spacer print

		for (i = 0; i < (unsigned int) spacer; i++) {
			*print++ = ' ';
			length--;
		}

		// Data print

		for (i = 0; i < cols_count; i++) {
			for (j = 0; j < cols; j++) {
				if (offset < size) {
					rc = snprintf(print, length, "%02X", *p);
					print += rc;
					length -= rc;

					p++;
					offset++;
					rollback++;
				} else {
					for (k = 0; k < 2; k++) {
						*print++ = ' ';
						length--;
					}
				}

				if (j != (cols - 1)) {
					*print++ = ' ';
					length--;
				}
			}

			if (i != (cols_count - 1)) {
				for (k = 0; k < 2; k++) {
					*print++ = ' ';
					length--;
				}
			}
		}

		// Spacer print

		for (i = 0; i < (unsigned int) spacer; i++) {
			*print++ = ' ';
			length--;
		}

		// ASCII print

		p -= rollback;
		offset -= rollback;

		for (i = 0; i < cols_count; i++) {
			for (j = 0; j < cols; j++) {
				if (offset < size) {
					if (isascii(*p) && isprint(*p))
						*print = *p;
					else
						*print = '.';

					print++;
					length--;

					p++;
					offset++;
					rollback++;
				}
			}

			if (i != (cols_count - 1) && offset < size) {
				*print++ = ' ';
				length--;
			}
		}

		*print = '\0';

		RIL_LOGD("%s", string);
	}

	return 0;
}

int strings_array_free(char **array, size_t size)
{
	unsigned int count;
	unsigned int i;

	if (array == NULL)
		return -1;

	if (size == 0) {
		for (i = 0; array[i] != NULL; i++)
			free(array[i]);
	} else {
		count = size / sizeof(char *);
		if (count == 0)
			return -1;

		for (i = 0; i < count; i++) {
			if (array[i] != NULL)
				free(array[i]);
		}
	}

	return 0;
}

int eventfd_flush(int fd)
{
	eventfd_t flush;
	int rc;

	rc = eventfd_read(fd, &flush);
	if (rc < 0)
		return -1;

	return 0;
}

int eventfd_recv(int fd, eventfd_t *event)
{
	int rc;

	rc = eventfd_read(fd, event);
	if (rc < 0)
		return -1;

	return 0;
}

int eventfd_send(int fd, eventfd_t event)
{
	int rc;

	eventfd_flush(fd);

	rc = eventfd_write(fd, event);
	if (rc < 0)
		return -1;

	return 0;
}
