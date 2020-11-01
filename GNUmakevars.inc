# Prerequisite: LEEC_TOP must be set.

# Useful to target for example the root of the current layer (ex: to locate the
# relevant, layer-local '_build' directory):
#
ifndef LAYER_TOP
	LAYER_TOP := $(LEEC_TOP)
endif


# Project section.

# PROJECT_NAME should be defined on a per-project basis.
ifndef PROJECT_NAME
	# Namely letsencrypt-erlang-ceylan:
	PROJECT_NAME := leec
endif


# REBAR3_PROJECT_NAME should be defined on a per-project basis.
ifndef REBAR3_PROJECT_NAME
	REBAR3_PROJECT_NAME := letsencrypt
endif


# The uniquely-defined version of this layer, for all uses (including rebar and
# hex):
#
LE_VERSION := 1.0.0


# PROJECT_VERSION should be defined on a per-project basis.
ifndef PROJECT_VERSION
	PROJECT_VERSION := $(LE_VERSION)
endif


ifndef PACKAGE_TOP
	PACKAGE_TOP = $(LEEC_TOP)
endif


# For any quick, local, non release-packaged update thereof:
MYRIAD_CHECKOUT_BUILD = $(LAYER_TOP)/_checkouts/myriad
MYRIAD_SIBLING_BUILD = $(LAYER_TOP)/../myriad


# The OTP tree of the Myriad application within a local OTP _build tree:
MYRIAD_LOCAL_APP := $(LAYER_TOP)/_build/default/lib/myriad

# Where Myriad BEAMs are to lie when used as an OTP application:
MYRIAD_LOCAL_EBIN := $(MYRIAD_LOCAL_APP)/ebin



LEEC_RELEASE_BASE := letsencrypt-$(PROJECT_VERSION)

LEEC_RELEASE_ARCHIVE_ZIP := $(LEEC_RELEASE_BASE).zip
LEEC_RELEASE_ARCHIVE_BZ2 := $(LEEC_RELEASE_BASE).tar.bz2
LEEC_RELEASE_ARCHIVE_XZ  := $(LEEC_RELEASE_BASE).tar.xz


# Source section.
LEEC_SRC := $(LEEC_TOP)/src

# BEAM path section.
LEEC_BEAM := $(LEEC_SRC)

# Include path section.
LEEC_INC = -I$(LEEC_TOP)/include


ERLANG_COMPILER_BASE_WARNING_OPT = -W2 +warn_export_all +warn_export_vars +warn_shadow_vars +warn_obsolete_guards +warn_unused_import +warnings_as_errors

# In an OTP/rebar3-style application layout, at compilation time, libraries
# making use of Myriad will expect its includes to be located in:
#
MYRIAD_OTP_INC := -I$(LEEC_TOP)/../myriad/include/

INC += $(LEEC_INC) $(MYRIAD_OTP_INC)


# See Myriad counterpart variable (MYRIAD_BEAM_DIRS) for explanations:
LEEC_BEAM_DIRS := $(LEEC_BEAM)


# For OTP releases and all:

LEEC_REBAR_BUILD_BASE = $(REBAR_BUILD_DIR)/lib/letsencrypt


# See Myriad counterpart variable (MYRIAD_BEAM_DIRS) for explanations:
LEEC_BEAM_DIRS = $(LEEC_TOP)/src


# We rely on Myriad as well:
BEAM_DIRS += $(LEEC_BEAM_DIRS)



ifndef VM_TEST_NAME
	VM_NAME := leec_debug
endif


ifndef VM_TEST_NAME
	VM_TEST_NAME := leec_test
endif



# Overall settings section.

# One may define here:
# EXECUTION_TARGET := production / development [the default]
# ENABLE_LEEC_DEBUG := false / true [the default]


# Tells whether the debug mode will be activated for the next LEEC modules to be
# built (maximum performance versus extended checkings).
#
ifeq ($(ENABLE_LEEC_DEBUG),true)
	LEEC_DEBUG_OPT := -DDEBUG_LEEC -DLEEC_ENABLE_LOG=1
else
	LEEC_DEBUG_OPT := -DLEEC_ENABLE_LOG=0
endif



# Build section.



# Compiler section.


# Checking section.

# For later reuse in the next layer of the software stack:
LEEC_PLT_FILE := $(LEEC_TOP)/leec.plt


# This is the merged PLT of the level just below in the software stack.
# For 'Letsencrypt', it is the PLT of 'Myriad':
ifndef PREDECESSOR_PLT
	PREDECESSOR_PLT = $(MYRIAD_PLT_FILE)
endif


# Prererequisites are supposedly already available and built thanks to rebar3:
PREREQ_ROOT = $(LEEC_TOP)/_build/default/lib


# We define the path to the Myriad layer (possibly available as a symbolic
# link).
#
# For the sake of these build-related makefiles, Ceylan dependencies may be
# found either in a local _checkouts child directory (if checkout directories
# are used and if the top-level package of interest is the current one), or in
# sibling directories (i.e. whose build root is at the same level as this one).
#
# This means that a Ceylan build will ignore the Myriad version in PREREQ_ROOT
# and use instead one defined just below.

# This last case happens notably if not using checkout directories, or if using
# them and if all the packages mentioned here are themselves dependencies (in
# which case they are all sitting together in the _checkouts child directory).
#
# Note also we rely on the names of build roots (ex: myriad) as opposed to
# project/repository names (ex: Ceylan-Myriad):
#
ifneq ($(wildcard $(LEEC_TOP)/../myriad),)

	# By default, expect sibling directories:
	MYRIAD_TOP = $(LEEC_TOP)/../myriad

else

	# Otherwise assume a checkout one:
	ifneq ($(wildcard $(LEEC_TOP)/_checkouts/myriad),)

		MYRIAD_TOP = $(LEEC_TOP)/_checkouts/myriad

   else

		FORCE_EVAL := $(error Unable to find the build root of Ceylan-Myriad)

	endif

endif

# Other LEEC dependencies:

COWLIB_TOP       = $(PREREQ_ROOT)/cowlib
GUN_TOP          = $(PREREQ_ROOT)/gun
SHOTGUN_TOP      = $(PREREQ_ROOT)/shotgun
ELLI_TOP         = $(PREREQ_ROOT)/elli

ERLANG_COLOR_TOP = $(PREREQ_ROOT)/erlang_color
YAMERL_TOP       = $(PREREQ_ROOT)/yamerl
GETOPT_TOP       = $(PREREQ_ROOT)/getopt

JSX_TOP          = $(PREREQ_ROOT)/jsx
JIFFY_TOP        = $(PREREQ_ROOT)/jiffy

LEEC_EXTRA_DEPS = $(COWLIB_TOP) $(GUN_TOP) $(SHOTGUN_TOP)       \
				  $(ELLI_TOP) $(ERLANG_COLOR_TOP) $(YAMERL_TOP) \
				  $(GETOPT_TOP) $(JSX_TOP) $(JIFFY_TOP)

# $(PREREQ_ROOT) is added, as most includes are expected to be done with
#  include_lib, hence as, for example, "elli/include/elli.hrl":
#
INC += $(foreach dir,$(LEEC_EXTRA_DEPS),-I$(dir)/include) -I$(PREREQ_ROOT)

BEAM_DIRS += $(foreach dir,$(LEEC_EXTRA_DEPS),$(dir)/ebin)