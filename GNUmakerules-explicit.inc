# Here are gathered explicit (immediate, static) rules for Leec.
#
# See GNUmakerules-automatic.inc for their automatic (generic, pattern-based)
# counterparts.


# Prerequisite: LEEC_TOP must be set.


.PHONY: default-leec-rule

# The first non-generic, therefore default, rule:
default-leec-rule: all
