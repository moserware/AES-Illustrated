using System;
using System.Text;

namespace Moserware.AesIllustrated
{
    /// <summary>
    /// Represents a matrix of bytes.
    /// </summary>    
    internal class ByteMatrix
    {
        private readonly byte[,] _ActualMatrix;

        public ByteMatrix(int rows, int columns)
        {
            Rows = rows;
            Columns = columns;
            _ActualMatrix = new byte[rows,columns];
        }

        public ByteMatrix(int rows, byte[] bytes)
            : this(rows, bytes.Length/rows)
        {
            for (int col = 0; col < Columns; col++)
            {
                for (int row = 0; row < Rows; row++)
                {
                    _ActualMatrix[row, col] = bytes[(col*Rows) + row];
                }
            }
        }

        public byte this[int row, int column]
        {
            get { return _ActualMatrix[row, column]; }
            set { _ActualMatrix[row, column] = value; }
        }

        public ByteMatrixColumn LastColumn
        {
            get { return GetColumn(Columns - 1); }
        }

        public int Rows { get; private set; }

        public int Columns { get; private set; }

        public ByteMatrixColumn GetColumn(int column)
        {
            return new ByteMatrixColumn(this, column);
        }

        public ByteMatrixRow GetRow(int row)
        {
            return new ByteMatrixRow(this, row);
        }

        public byte[] ToByteArray()
        {
            byte[] result = new byte[Rows*Columns];

            for (int col = 0; col < Columns; col++)
            {
                for (int row = 0; row < Rows; row++)
                {
                    result[(col*Rows) + row] = _ActualMatrix[row, col];
                }
            }

            return result;
        }

        public void Xor(ByteMatrix other)
        {
            ForEachCell((row, col) => (byte) (this[row, col] ^ other[row, col]));
        }

        public ByteMatrix SubMatrix(int startColumn, int totalColumns)
        {
            ByteMatrix result = new ByteMatrix(Rows, totalColumns);
            for (int col = startColumn; col < (startColumn + totalColumns); col++)
            {
                for (int row = 0; row < Rows; row++)
                {
                    result[row, col - startColumn] = this[row, col];
                }
            }

            return result;
        }

        public void ForEachCell(Func<int, int, byte> rowColumnByteProducer)
        {
            for (int col = 0; col < Columns; col++)
            {
                for (int row = 0; row < Rows; row++)
                {
                    this[row, col] = rowColumnByteProducer(row, col);
                }
            }
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();

            for(int row = 0; row < Rows; row++)
            {
                sb.Append("| ");
                for(int col = 0; col < Columns; col++)
                {
                    sb.Append(this[row, col].ToString("X2"));
                    sb.Append(" ");
                }
                sb.AppendLine("|");
            }

            return sb.ToString();
        }
    }

    /// <summary>
    /// Represents a single column in a <see cref="ByteMatrix"/>.
    /// </summary>
    internal class ByteMatrixColumn
    {
        private readonly int _Column;
        private readonly ByteMatrix _Matrix;

        public ByteMatrixColumn(ByteMatrix matrix, int column)
        {
            _Matrix = matrix;
            _Column = column;
        }

        public byte this[int row]
        {
            get { return _Matrix[row, _Column]; }
            set { _Matrix[row, _Column] = value; }
        }
    }

    /// <summary>
    /// Represents a single row in a <see cref="ByteMatrix"/>.
    /// </summary>
    internal class ByteMatrixRow
    {
        private readonly ByteMatrix _Matrix;
        private readonly int _Row;

        public ByteMatrixRow(ByteMatrix matrix, int row)
        {
            _Matrix = matrix;
            _Row = row;
        }

        public byte this[int column]
        {
            get { return _Matrix[_Row, column]; }
            set { _Matrix[_Row, column] = value; }
        }
    }
}