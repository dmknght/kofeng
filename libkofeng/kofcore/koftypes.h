/*
 * koftypes.h - the types a scan is asked with and answers with: the result, its
 * findings, the level words, the object-name vocabulary, the options, the
 * callbacks and the statistics.
 *
 * In core and not in kofeng.h because every layer of the engine fills or reads
 * these types: the detectors write findings, the verdictor composes the
 * verdict, the scanners take the options and hand the result out. They were
 * defined in the public API header, which put each of those layers above the
 * API. kofeng.h keeps the functions and includes this file, so a host still
 * needs only <kofeng.h>.
 *
 * The three parts, by purpose: kofobjname.h (the object-name vocabulary), kofresult.h
 * (what a scan answers with) and kofoption.h (what it is asked with and the
 * callbacks). This umbrella includes them all, so a host's include does not move.
 */

#ifndef KOFTYPES_H
#define KOFTYPES_H

#include <stdint.h>
#include <stddef.h>

#include <kofmod/infected.h>

#include "kofobjname.h"
#include "kofresult.h"
#include "kofoption.h"

#endif /* KOFTYPES_H */
