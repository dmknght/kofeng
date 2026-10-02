/*
 * peinfect_00.c - a PE that was modified after it was linked, which is what a
 * file infector leaves behind.
 *
 *
 * WHY A HEURISTIC AND NOT A SIGNATURE, which is the whole argument.
 *
 * A polymorphic file infector re-encodes its decryptor for every file it
 * infects. Measured on the four Sality samples here, the bytes at their entry
 * points share NOTHING:
 *
 *     f6c69cf28bd20faff20fbeed434684c7...
 *     6033d886c38d3d3d0c9fe60fc1c86a00...
 *     f6c2c4f7c0fa360e32eb020fcd750769...
 *     e800000000 5d 0f6ed5 0f7ed7 81c70c020000 57 b477 c3
 *
 * and the encrypted body shares nothing either: intersecting the 12-byte
 * substrings of all four last sections leaves ONE, and it is twelve zeroes.
 * The key is per sample, so even a key-independent transform finds nothing -
 * XOR-differencing the bodies at every stride from 1 to 16 gives 0.0% agreement
 * at every one.
 *
 * So there is no byte pattern to write, and that is not a gap in this file's
 * research: a signature over a stream of bytes, or over a stream of mnemonics,
 * identifies one GENERATION of a generator and not the family. What is left is
 * what the virus had to CHANGE about the file in order to run at all - and
 * that it cannot vary, because those changes are what make it execute.
 *
 *
 * WHAT IT HAD TO CHANGE, AND WHAT EACH ONE COSTS IN FALSE POSITIVES
 *
 * Measured over the 1680 PE32 of one Bazaar collection, against 4 of 4 Sality:
 *
 *   entry section is WRITABLE and executable       47  2.80%     4 of 4
 *   the LAST section is executable                 17  1.01%     4 of 4
 *   the entry point is IN the last section         11  0.66%     1 of 4
 *   two separate executable sections                6  0.36%     3 of 4
 *   the first two together                          1  0.06%     4 of 4
 *
 * Each is something a linker does not emit. A compiler's .text is R+X and its
 * .rsrc is R; a virus that writes its decryptor into the entry's section has
 * to make that section writable, and a virus that runs its body from the last
 * section has to make that one executable. The pair is what this fires on.
 *
 * THE THIRD TERM IS THE CLASSIC ONE AND IT IS THE WEAKEST HERE. "The entry
 * point is in the last section" is the evidence the public write-ups name
 * first for Sality and Virut, and on this sample set it is right about one file
 * in four - these are the entry-point-obfuscating builds, which patch the code
 * AT the entry and leave the entry itself alone. It is kept as evidence and not
 * as the test.
 *
 *
 * WHAT THIS MEASUREMENT IS NOT. The percentages above are against a MALWARE
 * corpus, because no clean Windows corpus exists on the machine this was
 * measured on. "0.06% of malware" is not a false-positive rate and must not be
 * read as one. It is a statement that the shape is rare even among hostile
 * files, which is the weaker claim the evidence supports.
 *
 *
 * TWO OUTCOMES, AND THE DIFFERENCE IS DELIBERATE
 *
 * HIT when both permissions were changed: that is a file whose layout only a
 * writer of code into someone else's program produces, and it is worth saying
 * so on its own.
 *
 * AND NOTHING AT ALL WHEN ONLY ONE OF THEM WAS, which is a correction.
 *
 * There used to be a second outcome here: one permission changed meant
 * KOF_HEUR_ACT - interpret the object, claim nothing - on the argument that
 * the run was worth its cost because what comes out of it is what gets named.
 * MEASURED, IT WAS NOT. That branch fires on about four percent of PE objects,
 * and over a 4712-file corpus it cost 5.1 seconds - 38.81 against 33.68 - for
 * ONE extra object and NOT ONE extra detection. Most of it went on Themida
 * children, where the interpreter ran twenty-five million instructions and
 * recovered a single 8 KB page.
 *
 * The samples this rule was written for are unaffected, because the module
 * that can name them vouches for its own run: all four Sality files are still
 * detected and repaired with this gone.
 *
 * So the rule reports when it is sure and is silent otherwise, and the
 * interpreter is asked for on the 0.06% of objects whose shape earns it rather
 * than on the 4% that merely resemble it. That is what a static exclusion
 * phase is for - deciding before any emulation whether emulation is worth
 * doing, from the file's gross structure alone.
 */

#include <kofmod/heur.h>
#include <kofmod/pe.h>

KOF_TARGET_FORMAT(KOF_FMT_PE);

/*
 * EXAMINE, because every term here is a field of the parse and none of them
 * needs the object opened.
 */
KOF_HEUR_PHASE(KOF_HEUR_EXAMINE);
/*
 * "Patched" AND NOT "Infected", because the type already says it.
 *
 * The verdict reads <Type>:<Family>, so KOF_HEUR_NAME("Infected") under
 * KOF_MALTYPE_VIRUS printed `Virus:Infected` - the same fact twice, with the
 * family slot wasted saying what the type had said. The slot is for WHAT WAS
 * RECOGNISED, and what this recognises is a program written into after it
 * was linked: the entry section made writable, the last one made executable.
 * `Virus:Patched` says which virus-shaped thing was seen.
 */
KOF_HEUR_NAME("Patched");


/*
 * NO PREDICTION. The shape says a file infector modified this program; it does
 * not say which one, and the three distinct section layouts among four samples
 * of ONE family are the reason not to guess. Whatever the run recovers is what
 * gets named.
 */
/*
 * AND IT DOES NOT CONCLUDE - see KOF_ENG_CONCLUDE, and the measurement that
 * settled it.
 *
 * "This PE was modified after it was linked" reads like a verdict and is not
 * one: it is the SHAPE a file infector leaves, and which infector - and
 * whether the host can be given back - is what the unpacker underneath
 * answers. Declaring KOF_ENG_CONCLUDE here stopped the chain before that
 * unpacker ran, and on the four Sality samples it turned three
 * `Virus:Sality#Body` into three `Heur:Infected`: a named family and its
 * repair traded for the shape that led to them. The fourth is the one this
 * rule deliberately does not fire on.
 *
 * So this is a survey rule, and the verdict belongs to whatever comes out.
 */
KOF_HEUR_WANT(KOF_ENG_USE_EMU);

/*
 * AND WHICH KIND OF THING TO LOOK FOR NEXT. A file infector modified this
 * program, so the modules worth asking are the ones that know viruses - see
 * KOF_HEUR_SCAN_CLASS. The packers are still asked: an infected file is
 * routinely packed too, and the body is underneath.
 */
KOF_HEUR_SCAN_CLASS(KOF_MALTYPE_VIRUS);

KOF_DEFINE_HEUR
{
	const struct kof_pe_info *p = kof_pe(ctx);
	const struct kof_pe_sec *ep, *last;
	int wx, lastx;

	if (!p || !p->valid || !p->sec_count)
		return;
	if (p->entry_sec >= p->sec_count)
		return;
	ep = &p->sec[p->entry_sec];
	last = &p->sec[p->sec_count - 1u];

	wx = (ep->perm & (KOF_PE_PERM_W | KOF_PE_PERM_X)) ==
	     (KOF_PE_PERM_W | KOF_PE_PERM_X);
	lastx = (last->perm & KOF_PE_PERM_X) != 0;

	/*
	 * ONE SECTION IS NOT TWO PIECES OF EVIDENCE. A program linked into a
	 * single section has its entry section and its last section in the same
	 * place, so `lastx` is then only `ep` executable said twice - which is
	 * true of every program ever linked. Measured: 8ef99966 is exactly this
	 * file, and without the test it would fire on the strength of one fact
	 * counted twice.
	 */
	if (p->sec_count > 1u && wx && lastx)
		KOF_HEUR_HIT();
}
