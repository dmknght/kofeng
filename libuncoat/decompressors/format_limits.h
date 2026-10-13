/*
 * format_limits.h - what the LZMA and LZX formats allow, as numbers.
 *
 * DEFINED BY libuncoat: they are properties of the formats the decoders
 * implement, and the decoders check them. The engine re-exports this header
 * from <kofmod/kofsig.h> because a module reads them out of a container and has
 * to refuse what is out of range before it asks for a decode.
 */
#ifndef KUNCOAT_FORMAT_LIMITS_H
#define KUNCOAT_FORMAT_LIMITS_H

/*
 * What the LZMA specification allows for each parameter.
 *
 * Module facing because a module is what reads them out of a container and has to
 * refuse the ones that are out of range - they size the decoder's probability
 * model, so an unchecked value is an allocation chosen by whoever wrote the file.
 * The decoder checks them again on its own side; this is so a module can say it
 * could not finish rather than being refused with nothing to report.
 */
#define KUNCOAT_LZMA_MAX_LC 8u
#define KUNCOAT_LZMA_MAX_LP 4u
#define KUNCOAT_LZMA_MAX_PB 4u

/*
 * The window sizes LZX defines: 2^15 to 2^21.
 *
 * Module facing for the reason KUNCOAT_LZMA_MAX_LC is - a module is what reads the
 * width out of a container, a cabinet's typeCompress or a help file's
 * ControlData, and has to refuse one the format never defines rather than pass
 * it on as a method id nothing decodes.
 */
#define KUNCOAT_LZX_MIN_BITS 15u
#define KUNCOAT_LZX_MAX_BITS 21u

#endif /* KUNCOAT_FORMAT_LIMITS_H */
