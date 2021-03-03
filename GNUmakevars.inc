# Prerequisite: LEEC_TOP must be set.


# To understand why taking into account such conditionals requires to specify
# them first, and in each layer, rather than at the end of the last one, refer
# to the section about conditionals at the top of the GNUmakevars.inc of Myriad.


# Overall settings section.

#EXECUTION_TARGET = production

ifndef EXECUTION_TARGET

	# Other possible value: production
	EXECUTION_TARGET = development

endif


ifeq ($(EXECUTION_TARGET),development)

	#$(info Execution target is development)

	ENABLE_DEBUG = true

else ifeq ($(EXECUTION_TARGET),production)

	#$(info Execution target is production)

	ENABLE_DEBUG = false

else

	$(error Invalid LEEC execution target '$(EXECUTION_TARGET)'; expecting either 'development' or 'production')

endif


# One may define here:
# EXECUTION_TARGET := production / development [the default]
# ENABLE_DEBUG := false / true [the default]


# Tells whether the debug mode will be activated for the next LEEC modules to be
# built (maximum performance versus extended checkings).
#
ifeq ($(ENABLE_DEBUG),true)
	LEEC_DEBUG_OPT := -DDEBUG_LEEC -DLEEC_ENABLE_LOG=1
	ENABLE_LEEC_DEBUG_OPT = -Dleec_debug_mode
else
	LEEC_DEBUG_OPT := -DLEEC_ENABLE_LOG=0
	ENABLE_LEEC_DEBUG_OPT =
endif


# Defining (optional) layer-specific flags, typically used by in-code
# conditional compilation primitives (see cond_utils for their management):

# Topics covered by flags:
# - fsm: regarding the finite state machine (ex: state changes) and general
#   operations
#  - keys: regarding all kinds of keys and certificates
#  - network: regarding network elements such as TCP connections
#  - exchanges: regarding the exchanges with ACME servers
#  - codec: regarding encoding/decoding activities
#  - sni: regarding Server Name Indication
#
# Defining debug flags (at least the most verbose are by default commented-out):
ifeq ($(ENABLE_DEBUG),true)
	LEEC_DEBUG_FLAGS += -Dleec_debug_fsm
	LEEC_DEBUG_FLAGS += -Dleec_debug_keys
	LEEC_DEBUG_FLAGS += -Dleec_debug_network
	LEEC_DEBUG_FLAGS += -Dleec_debug_exchanges
	LEEC_DEBUG_FLAGS += -Dleec_debug_codec
	LEEC_DEBUG_FLAGS += -Dleec_debug_sni
endif

# Defining check flags:
ifeq ($(EXECUTION_TARGET),development)
	# Does not exist: LEEC_CHECK_FLAGS += -Dleec_check_xx
endif


ERLANG_COMPILER_OPT_BASE += $(LEEC_DEBUG_FLAGS) \
							$(LEEC_CHECK_FLAGS)



# Useful to target for example the root of the current layer (ex: to locate the
# relevant, layer-local '_build' directory):
#
ifndef LAYER_TOP
	LAYER_TOP := $(LEEC_TOP)
endif


# Project section.

# PROJECT_NAME should be defined on a per-project basis.
ifndef PROJECT_NAME
	# Namely Let's Encrypt Erlang Ceylan:
	PROJECT_NAME := Ceylan-LEEC
endif


# REBAR3_PROJECT_NAME should be defined on a per-project basis.
ifndef PROJECT_NAME_FOR_REBAR
	PROJECT_NAME_FOR_REBAR := leec
endif


# The uniquely-defined version of this layer, for all uses (including rebar and
# hex):
#
LEEC_VERSION := 0.7.0


# PROJECT_VERSION should be defined on a per-project basis.
ifndef PROJECT_VERSION
	PROJECT_VERSION := $(LEEC_VERSION)
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



LEEC_RELEASE_BASE := Ceylan-LEEC-$(PROJECT_VERSION)

LEEC_RELEASE_ARCHIVE_ZIP := $(LEEC_RELEASE_BASE).zip
LEEC_RELEASE_ARCHIVE_BZ2 := $(LEEC_RELEASE_BASE).tar.bz2
LEEC_RELEASE_ARCHIVE_XZ  := $(LEEC_RELEASE_BASE).tar.xz


# Source section.
LEEC_SRC := $(LEEC_TOP)/src

# BEAM path section.
LEEC_BEAM := $(LEEC_SRC)

# Include path section.
LEEC_INC = -I$(LEEC_TOP)/include


# In an OTP/rebar3-style application layout, at compilation time, libraries
# making use of Myriad will expect its includes to be located in:
#
MYRIAD_OTP_INC := -I$(LEEC_TOP)/../myriad/include/

INC += $(LEEC_INC) $(MYRIAD_OTP_INC)


# See Myriad counterpart variable (MYRIAD_BEAM_DIRS) for explanations:
LEEC_BEAM_DIRS := $(LEEC_BEAM)


# For OTP releases and all:

LEEC_REBAR_BUILD_BASE = $(REBAR_BUILD_DIR)/lib/leec


# When building LEEC in an OTP context from its usual (GIT) root (ex: with
# 'make rebar3-application'), the BEAMs of Myriad are to be found in the OTP
# build tree - rather than in a supposedly fully-built usual root for Myriad:
#
# (these information are useful only at compilation-time, in order to locate the
# needed parse transforms and their dependencies; at runtime, the OTP rules
# ensure that the relevant ebin directories are in the code path)
#
# Note that this implies that the BEAM files in all ebin directories should be
# up to date with the ones in the build trees, otherwise hard-to-debug
# discrepancies may happen (these OTP/rebar-related directories act as default
# catch-alls, should no prior directory correspond in the BEAM paths).
#
MYRIAD_OTP_BEAM_DIR_FROM_USUAL = $(LAYER_TOP)/$(MYRIAD_REBAR_BUILD_BASE)/ebin


# In an OTP/rebar3-style application layout (not speaking of sibling base
# directories here), at compilation time as well, modules compiled (directly or
# not) by the Myriad parse transform will expect its modules to be located in:
#
# (a third place could be considered, in the _build tree of Myriad itself, yet
# it would not provide any additional chance)
#
MYRIAD_OTP_BEAM_DIR_FROM_OTP = $(LAYER_TOP)/../myriad/ebin/


# To locate Myriad modules from all OTP contexts:
MYRIAD_PARSE_TRANSFORMS_PZ_OPT = -pz $(MYRIAD_OTP_BEAM_DIR_FROM_USUAL) \
								 -pz $(MYRIAD_OTP_BEAM_DIR_FROM_OTP)


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




# Build section.


# Compiler section.


#USE_SHOTGUN := true

# By default, in terms of HTTP client, LEEC uses (through Myriad's web_utils)
# the Erlang-native httpc library.
#
# Otherwise Shotgun may be used:
#
ifndef USE_SHOTGUN
	USE_SHOTGUN = false
endif

ifeq ($(USE_SHOTGUN),true)
	HTTPC_OPT = -Dmyriad_httpc_backend=shotgun
else
	HTTPC_OPT = -Dmyriad_httpc_backend=native_httpc
endif

ERLANG_COMPILER_OPT_BASE += $(HTTPC_OPT)



# Checking section.

# For later reuse in the next layer of the software stack:
LEEC_PLT_FILE := $(LEEC_TOP)/leec.plt


# This is the merged PLT of the level just below in the software stack.
# For 'LEEC', it is the PLT of 'Myriad':
ifndef PREDECESSOR_PLT
	PREDECESSOR_PLT = $(MYRIAD_PLT_FILE)
endif


# Prererequisites are supposedly already available and built as siblings,
# otherwise thanks to rebar3:

SIBLING_ROOT = $(LEEC_TOP)/..
PREREQ_ROOT = $(LEEC_TOP)/_build/default/lib


# We define the path to the Myriad layer (possibly available as a symbolic
# link).
#
# For the sake of these build-related makefiles, Ceylan dependencies will be
# searched (in that order, the one enforced in otp_utils) in a local _checkouts
# child directory (if checkout directories are used and if the top-level package
# of interest is the current one), otherwise in sibling directories (i.e. whose
# build root is at the same level as this one).
#
# This last case happens notably if not using checkout directories, or if using
# them and if all the packages mentioned here are themselves dependencies (in
# which case they are all sitting together in the _checkouts child directory).
#
# Note also we rely on the names of build roots (ex: myriad) as opposed to
# project/repository names (ex: Ceylan-Myriad):
#
# This means that a Ceylan build will ignore the Myriad version in PREREQ_ROOT
# and use instead one defined just below.
#
# This last case happens notably if not using checkout directories, or if using
# them and if all the packages mentioned here are themselves dependencies (in
# which case they are all sitting together in the _checkouts child directory).
#
# Note also that we rely on the names of build roots (ex: myriad) as opposed to
# project/repository names (ex: Ceylan-Myriad):
#
# First priority is an existing checkout directory:
ifneq ($(wildcard $(LEEC_TOP)/_checkouts/myriad/.),)
	MYRIAD_TOP = $(LEEC_TOP)/_checkouts/myriad
else
	# Second, a sibling one is searched for:
	ifneq ($(wildcard $(LEEC_TOP)/../myriad/.),)
		MYRIAD_TOP = $(LEEC_TOP)/../myriad
   else
		# Otherwise most probably in a 'rebar3 compile' context:
		ifneq ($(wildcard $(LEEC_TOP)/_build/default/lib/myriad/.),)
			MYRIAD_TOP = $(LEEC_TOP)/_build/default/lib/myriad
		else
			FORCE_EVAL := $(error Unable to find the build root of Ceylan-Myriad from $(realpath .).)
		endif
	endif
endif


# Other LEEC dependencies:

# We must ensure to select the same locations as otp_utils, otherwise some
# modules (typically of jsx) could be found more than once, which leads to a
# runtime error:

ifndef COWLIB_TOP
	ifneq ($(wildcard $(LEEC_TOP)/_checkouts/cowlib/.),)
		COWLIB_TOP = $(LEEC_TOP)/_checkouts/cowlib
	else
		ifneq ($(wildcard $(SIBLING_ROOT)/cowlib/.),)
			COWLIB_TOP = $(SIBLING_ROOT)/cowlib
		else
			COWLIB_TOP = $(PREREQ_ROOT)/cowlib
		endif
	endif
endif

ifndef GUN_TOP
	ifneq ($(wildcard $(LEEC_TOP)/_checkouts/gun/.),)
		GUN_TOP = $(LEEC_TOP)/_checkouts/gun
	else
		ifneq ($(wildcard $(SIBLING_ROOT)/gun/.),)
			GUN_TOP = $(SIBLING_ROOT)/gun
		else
			GUN_TOP = $(PREREQ_ROOT)/gun
		endif
	endif
endif

ifndef SHOTGUN_TOP
	ifneq ($(wildcard $(LEEC_TOP)/_checkouts/shotgun/.),)
		SHOTGUN_TOP = $(LEEC_TOP)/_checkouts/shotgun
	else
		ifneq ($(wildcard $(SIBLING_ROOT)/shotgun/.),)
			SHOTGUN_TOP = $(SIBLING_ROOT)/shotgun
		else
			SHOTGUN_TOP = $(PREREQ_ROOT)/shotgun
		endif
	endif
endif

ifndef ELLI_TOP
	ifneq ($(wildcard $(LEEC_TOP)/_checkouts/elli/.),)
		ELLI_TOP = $(LEEC_TOP)/_checkouts/elli
	else
		ifneq ($(wildcard $(SIBLING_ROOT)/elli/.),)
			ELLI_TOP = $(SIBLING_ROOT)/elli
		else
			ELLI_TOP = $(PREREQ_ROOT)/elli
		endif
	endif
endif

ifndef ERLANG_COLOR_TOP
	ifneq ($(wildcard $(SIBLING_ROOT)/erlang_color/.),)
		ERLANG_COLOR_TOP = $(SIBLING_ROOT)/erlang_color
	else
		ERLANG_COLOR_TOP = $(PREREQ_ROOT)/erlang_color
	endif
endif

ifndef YAMERL_TOP
	ifneq ($(wildcard $(LEEC_TOP)/_checkouts/yamerl/.),)
		YAMERL_TOP = $(LEEC_TOP)/_checkouts/yamerl
	else
		ifneq ($(wildcard $(SIBLING_ROOT)/yamerl/.),)
			YAMERL_TOP = $(SIBLING_ROOT)/yamerl
		else
			YAMERL_TOP = $(PREREQ_ROOT)/yamerl
		endif
	endif
endif

ifndef GETOPT_TOP
	ifneq ($(wildcard $(LEEC_TOP)/_checkouts/getopt/.),)
		GETOPT_TOP = $(LEEC_TOP)/_checkouts/getopt
	else
		ifneq ($(wildcard $(SIBLING_ROOT)/getopt/.),)
			GETOPT_TOP = $(SIBLING_ROOT)/getopt
		else
			GETOPT_TOP = $(PREREQ_ROOT)/getopt
		endif
	endif
endif

ifndef JSX_TOP
	ifneq ($(wildcard $(LEEC_TOP)/_checkouts/jsx/.),)
		JSX_TOP = $(LEEC_TOP)/_checkouts/jsx
	else
		ifneq ($(wildcard $(SIBLING_ROOT)/jsx/.),)
			JSX_TOP = $(SIBLING_ROOT)/jsx
		else
			JSX_TOP = $(PREREQ_ROOT)/jsx
		endif
	endif
endif

ifndef JIFFY_TOP
	ifneq ($(wildcard $(LEEC_TOP)/_checkouts/jiffy/.),)
		JIFFY_TOP = $(LEEC_TOP)/_checkouts/jiffy
	else
		ifneq ($(wildcard $(SIBLING_ROOT)/jiffy/.),)
			JIFFY_TOP = $(SIBLING_ROOT)/jiffy
		else
			JIFFY_TOP = $(PREREQ_ROOT)/jiffy
		endif
	endif
endif

LEEC_EXTRA_DEPS = $(COWLIB_TOP) $(GUN_TOP) $(SHOTGUN_TOP)       \
				  $(ELLI_TOP) $(ERLANG_COLOR_TOP) $(YAMERL_TOP) \
				  $(GETOPT_TOP) $(JSX_TOP) $(JIFFY_TOP)

# $(SIBLING_ROOT) and $(PREREQ_ROOT) are added, as most includes are expected to
# be done with include_lib, hence as, for example, "elli/include/elli.hrl":
#
INC += $(foreach dir,$(LEEC_EXTRA_DEPS),-I$(dir)/include) -I$(SIBLING_ROOT) -I$(PREREQ_ROOT)


# These directories are not added anymore here, as otp_utils will also add them
# programatically in the code path; moreover these paths would be transformed
# (in launch-erl.sh) through realpath, which would lead them to be added for
# example as NATIVE_BASE/leec/_build/default/lib/X instead of
# NATIVE_BASE/us_web/_checkouts/leec/_build/default/lib/X (ex: X being jsx),
# leading in turn the erroneous detection of duplicated BEAM files in the code
# path (ex: jsx.beam).
#
#BEAM_DIRS += $(foreach dir,$(LEEC_EXTRA_DEPS),$(dir)/ebin)