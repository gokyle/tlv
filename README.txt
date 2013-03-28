tlv.go

   Package tlv provides a toolkit for working with TLV (Tag-Length-Record)
   values and lists of TLVs, such as might be found in a binary file format
   or a network protocol.

   In this package, tags and lengths are represented as integers. A future
   revision will support tags and lengths other than an integer.

   The basic unit of the library is the TLVList. A new, empty TLVList can
   be created using the New function. A TLVList may be written to an
   io.Writer using the Write method, and may be read from a file using
   the Read function.

   tlv.go is licensed under the ISC license.
