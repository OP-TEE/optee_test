/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "adbg_int.h"

#include <stdlib.h>

#include <ctype.h>
/*************************************************************************
 * 2. Definition of external constants and variables
 ************************************************************************/

/*************************************************************************
 * 3. File scope types, constants and variables
 ************************************************************************/

/*************************************************************************
 * 4. Declaration of file local functions
 ************************************************************************/

/*************************************************************************
 * 5. Definition of external functions
 ************************************************************************/

/******************************************************************************/
/*! @fn void Do_ADBG_Log( void* This_p, char* Format, ...)
 * @brief
 * @param [in] This_p
 * @param [in] Format
 * @param [in] ...
 * @return void
 */
/******************************************************************************/
void Do_ADBG_Log(const char *const Format, ...)
{
	va_list ap;
	char buf[ADBG_STRING_LENGTH_MAX];

	va_start(ap, Format);
	vsnprintf(buf, sizeof(buf), Format, ap);
	va_end(ap);
	printf("%s\n", buf);
	fflush(stdout);
}

void Do_ADBG_LogHeading(unsigned Level, const char *const Format, ...)
{
	va_list List;
	char String[ADBG_STRING_LENGTH_MAX];
	char UnderLine;
	char Numbers[10];
	static int HeadingNumbers[3] = { 0, 0, 0 };

/* lint -save -e718 -e746 -e530 lint doesn't seem to know of va_start */
	va_start(List, Format);
/* lint -restore */
	(void)vsnprintf(String, sizeof(String), Format, List);
	va_end(List);

	switch (Level) {
	case 0:
		UnderLine = '#';
		HeadingNumbers[0] = HeadingNumbers[1] = HeadingNumbers[2] = 0;
		Numbers[0] = '\0';
		break;
	case 1:
		UnderLine = '=';
		HeadingNumbers[0]++;
		HeadingNumbers[1] = HeadingNumbers[2] = 0;
		(void)ADBG_snprintf(Numbers, sizeof(Numbers), "%d",
				    HeadingNumbers[0]);
		break;
	case 2:
		UnderLine = '~';
		HeadingNumbers[1]++;
		HeadingNumbers[2] = 0;
#if 0           /* Stupid snprintf bug only taking first argument */
		(void)ADBG_snprintf(Numbers, sizeof(Numbers), "%d.%d",
				    HeadingNumbers[0], HeadingNumbers[1]);
#else
		(void)ADBG_snprintf(Numbers, sizeof(Numbers), "%d.",
				    HeadingNumbers[0]);
		(void)ADBG_snprintf(Numbers + strlen(Numbers),
				    sizeof(Numbers) - strlen(Numbers),
				    "%d", HeadingNumbers[1]);
#endif
		break;
	case 3:
		UnderLine = '-';
		HeadingNumbers[2]++;
#if 0           /* Stupid snprintf bug only taking first argument */
		(void)ADBG_snprintf(Numbers, sizeof(Numbers), "%d.%d.%d",
				    HeadingNumbers[0], HeadingNumbers[1],
				    HeadingNumbers[2]);
#else
		(void)ADBG_snprintf(Numbers, sizeof(Numbers), "%d.",
				    HeadingNumbers[0]);
		(void)ADBG_snprintf(Numbers + strlen(Numbers),
				    sizeof(Numbers) - strlen(Numbers),
				    "%d.", HeadingNumbers[1]);
		(void)ADBG_snprintf(Numbers + strlen(Numbers),
				    sizeof(Numbers) - strlen(Numbers),
				    "%d", HeadingNumbers[2]);
#endif
		break;
	default:
		UnderLine = '-';
		Numbers[0] = '\0';
	}

	Do_ADBG_Log("%-5s %s", Numbers, String);

	if (String[0] != '\0') {
		size_t n;

		for (n = 0; String[n] != '\0'; n++)
			String[n] = UnderLine;

		Do_ADBG_Log("%-5s %s", "", String);
		if (Level == 0)
			Do_ADBG_Log(" ");
	}
}

void Do_ADBG_LogText(const char *const Text_p)
{
	static const ADBG_LogTableShapes_t Shapes = { ' ', ' ', ' ' };
	ADBG_LogTable_t LogTable[2] = { { 3, NULL }, { 74, NULL } };

	LogTable[1].Text_p = Text_p;
	Do_ADBG_LogTableShapes(&Shapes, LogTable, 2);
}

void Do_ADBG_LogHelp(
	const ADBG_HelpTable_t *const HelpTable_p,
	const size_t HelpTableLength
	)
{
	static const ADBG_LogTableShapes_t Shapes = { ' ', ' ', ' ' };
	ADBG_LogTable_t Row[2] = { { 20, NULL }, { 50, NULL } };
	size_t n;

	for (n = 0; n < HelpTableLength; n++) {
		Row[0].Text_p = HelpTable_p[n].Command_p;
		Row[1].Text_p = HelpTable_p[n].Help_p;
		Do_ADBG_LogTableShapes(&Shapes, Row, 2);
	}
}

void Do_ADBG_HexLog(
	const void *const Buf_p,
	const size_t Size,
	const size_t Cols
	)
{
	const uint8_t *Data_p = Buf_p;
	size_t n;

	for (n = 0; n < Size; n += Cols) {
		char HexBuffer[ADBG_STRING_LENGTH_MAX];
		char AsciiBuffer[ADBG_STRING_LENGTH_MAX / 3];
		size_t m, NumCols;

		(void)SecUtil_BufferToHex(Data_p + n, MIN(Cols, Size - n), NULL,
					  HexBuffer, sizeof(HexBuffer));
		NumCols = MIN(MIN(Cols, Size - n), sizeof(AsciiBuffer) - 1);
		for (m = 0; m < NumCols; m++) {
			int ch = Data_p[n + m];

			if (isprint(ch))
				AsciiBuffer[m] = (char)ch;
			else
				AsciiBuffer[m] = '.';
		}
		AsciiBuffer[m] = '\0';

		Do_ADBG_Log("  %-*s %s", (int)Cols * 3, HexBuffer, AsciiBuffer);
	}
}

void Do_ADBG_LogTable(
	const ADBG_LogTable_t *const TableRow_p,
	const size_t NumColumns
	)
{
	const ADBG_LogTableShapes_t Shapes = { '+', '|', '-' };

	Do_ADBG_LogTableShapes(&Shapes, TableRow_p, NumColumns);
}

void Do_ADBG_LogTableLine(
	const ADBG_LogTable_t *const TableRow_p,
	const size_t NumColumns
	)
{
	const ADBG_LogTableShapes_t Shapes = { '+', '|', '-' };

	Do_ADBG_LogTableShapesLine(&Shapes, TableRow_p, NumColumns);
}


void Do_ADBG_LogTableShapes(
	const ADBG_LogTableShapes_t *const Shapes,
	const ADBG_LogTable_t *const TableRow_p,
	const size_t NumColumns
	)
{
	char *Line_p;
	size_t *LastPos_p;
	size_t n;
	size_t TableColumn;
	size_t LinePosition;
	size_t LineLength;
	size_t NumColumnsLeft;

	LineLength = 2; /* Starting and ending '|' */
	for (n = 0; n < NumColumns; n++)
		LineLength += TableRow_p[n].ColumnWidth + 1; /* One extra '|' */

	Line_p = HEAP_UNTYPED_ALLOC(LineLength + 1);
	LastPos_p = HEAP_UNTYPED_ALLOC(sizeof(size_t) * NumColumns);
	if (Line_p == NULL || LastPos_p == NULL) {
		Do_ADBG_Log("Do_ADBG_LogTableLine: Memory allocation failed");
		goto CleanupReturn;
	}
	memset(LastPos_p, 0, sizeof(size_t) * NumColumns);

	do {
		NumColumnsLeft = NumColumns;
		LinePosition = 0;
		for (TableColumn = 0; TableColumn < NumColumns; TableColumn++) {
			const ADBG_LogTable_t *Col_p = TableRow_p + TableColumn;
			size_t TextLen = 0;
			size_t ColumnPos;

			if (Col_p->Text_p != NULL)
				TextLen = strlen(Col_p->Text_p);

			Line_p[LinePosition] = Shapes->Vertical;
			LinePosition++;

			if (Col_p->ColumnWidth <= 1) {
				NumColumnsLeft--;
				continue;
			}

			Line_p[LinePosition] = ' ';
			LinePosition++;

			if (Col_p->ColumnWidth <= 2) {
				NumColumnsLeft--;
				continue;
			}

			n = LastPos_p[TableColumn];
			ColumnPos = 1;
			while (n < TextLen && ColumnPos < Col_p->ColumnWidth) {
				size_t WordLength;
				size_t NewLine = 0;

				/*
				 * We copy one complete word at a time.
				 * If the word is too long
				 * to fit in the column at all
				 * it's broken at the end of the
				 * column.
				 */

				/* Consume leading spaces  */
				while (n < TextLen && Col_p->Text_p[n] == ' ')
					n++;

				/* Find out the length of the word */
				WordLength = 0;
				while ((n + WordLength) < TextLen &&
				       Col_p->Text_p[n + WordLength] != ' ') {
					if (Col_p->Text_p[n + WordLength] ==
					    '\n') {
						NewLine = 1;
						break;
					}
					/*
					 * The -1 for ColumnWidth is
					 *  to make room for a final space
					 * before the '|'.
					 */
					if ((ColumnPos + WordLength) >=
					    (Col_p->ColumnWidth - 1)) {
						if (ColumnPos != 1) {
							/* Save this word
							for the next line */
							WordLength = 0;
						}
						break;
					}
					WordLength++;
				}

				/* Copy the word and update the positions */
				memcpy(Line_p + LinePosition, Col_p->Text_p + n,
				       WordLength);
				n += WordLength + NewLine;
				LinePosition += WordLength;
				ColumnPos += WordLength;

				/* Now output all spaces */

				if (WordLength == 0) {
					/* The spaces will be added
					in the outer loop */
					break;
				}

				/*
				 * If there's spaces in the text at the
				 * current position
				 * and there's room for one, output one space.
				 * The rest of the spaces are consumed in
				 *  the inner loop
				 * above. This will take an additional line if
				 * the spaces
				 * are at the end of the Text_p but you're not
				 * supposed end a Text_p with spaces any way.
				 */
				if (Col_p->Text_p[n] == ' ' && ColumnPos <
				    Col_p->ColumnWidth) {
					Line_p[LinePosition] = ' ';
					LinePosition++;
					ColumnPos++;
					n++;
				}
			}
			LastPos_p[TableColumn] = n;

			if (LastPos_p[TableColumn] == TextLen)
				NumColumnsLeft--;

			/* Output spaces until the end of the column */
			while (ColumnPos < Col_p->ColumnWidth) {
				Line_p[LinePosition] = ' ';
				LinePosition++;
				ColumnPos++;
			}
		}

		Line_p[LinePosition] = Shapes->Vertical;
		LinePosition++;
		Line_p[LinePosition] = '\0';
		Do_ADBG_Log("%s", Line_p);
	} while (NumColumnsLeft > 0);

CleanupReturn:
	HEAP_FREE(&Line_p);
	HEAP_FREE(&LastPos_p);
}

void Do_ADBG_LogTableShapesLine(
	const ADBG_LogTableShapes_t *const Shapes,
	const ADBG_LogTable_t *const TableRow_p,
	const size_t NumColumns
	)
{
	char *Line_p;
	size_t n;
	size_t TableColumn;
	size_t LinePosition;
	size_t LineLength;

	LineLength = 2; /* Starting and ending '+' */
	for (n = 0; n < NumColumns; n++)
		LineLength += TableRow_p[n].ColumnWidth + 1; /* One extra '+' */

	Line_p = HEAP_UNTYPED_ALLOC(LineLength + 1);
	if (Line_p == NULL) {
		Do_ADBG_Log("Do_ADBG_LogTableLine: Memory allocation failed");
		goto CleanupReturn;
	}

	LinePosition = 0;
	for (TableColumn = 0; TableColumn < NumColumns; TableColumn++) {
		Line_p[LinePosition] = Shapes->Corner;
		LinePosition++;
		for (n = 0; n < TableRow_p[TableColumn].ColumnWidth; n++) {
			Line_p[LinePosition] = Shapes->Horizontal;
			LinePosition++;
		}
	}
	Line_p[LinePosition] = Shapes->Corner;
	LinePosition++;
	Line_p[LinePosition] = '\0';
	Do_ADBG_Log("%s", Line_p);

CleanupReturn:
	HEAP_FREE(&Line_p);
}

/*************************************************************************
 * 6. Definitions of internal functions
 ************************************************************************/
