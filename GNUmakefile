LEEC_TOP = .


.PHONY: all-rebar help help-intro help-leec                              \
		all register-version-in-header register-leec test-leec           \
		list-beam-dirs add-prerequisite-plts link-plt                    \
		send-release release release-zip release-bz2 release-xz          \
		prepare-release clean-release clean-archive                      \
		check-types check-cross-references info-paths info-compile

MODULES_DIRS = src #doc test priv


# To override the 'all' default target with a parallel version:
BASE_MAKEFILE = true


LEEC_RELEASES = $(LEEC_RELEASE_ARCHIVE_BZ2) \
				$(LEEC_RELEASE_ARCHIVE_ZIP) \
				$(LEEC_RELEASE_ARCHIVE_XZ)

all: all-rebar

all-rebar:
	@$(REBAR3_EXEC) upgrade
	@$(REBAR3_EXEC) compile


# First target for default:
help: help-intro help-leec


help-intro:
	@echo " Following main make targets are available for package $(PACKAGE_NAME):"


help-leec:
	@cd $(MYRIAD_TOP) && $(MAKE) -s help-myriad


register-version-in-header:
	@if [ -z "$(VERSION_FILE)" ] ; then \
	echo "Error, no version file defined." 1>&2 ; exit 51 ; else \
	$(MAKE) register-leec ; fi


register-leec:
	@echo "-define( leec_version, \"$(LEEC_VERSION)\" )." >> $(VERSION_FILE)


test-leec:
	@bin/eletsencrypt --config etc/leec-test.yml


# Useful to extract internal layout for re-use in upper layers:
list-beam-dirs:
	@for d in $(LEEC_BEAM_DIRS) ; do echo $$(readlink -f $$d) ; done


add-prerequisite-plts: link-plt


# As upper layers may rely on the 'leec' naming:
link-plt:
	@/bin/ln -s --force $(PLT_FILE) $(LEEC_PLT_FILE)



release: release-zip release-bz2 release-xz
	@$(MAKE) clean-release


release-zip: prepare-release
	@echo "     Creating Leec release archive $(LEEC_RELEASE_ARCHIVE_ZIP)"
	@cd .. && zip -r $(LEEC_RELEASE_ARCHIVE_ZIP) $(LEEC_RELEASE_BASE) \
	&& echo "     Archive $(LEEC_RELEASE_ARCHIVE_ZIP) ready in "`pwd`


release-bz2: prepare-release
	@echo "     Creating Leec release archive $(LEEC_RELEASE_ARCHIVE_BZ2)"
	@cd .. && tar chvjf $(LEEC_RELEASE_ARCHIVE_BZ2) $(LEEC_RELEASE_BASE) \
	&& echo "     Archive $(LEEC_RELEASE_ARCHIVE_BZ2) ready in "`pwd`


release-xz: prepare-release
	@echo "     Creating Leec release archive $(LEEC_RELEASE_ARCHIVE_XZ)"
	@cd .. && tar chvjf $(LEEC_RELEASE_ARCHIVE_XZ) $(LEEC_RELEASE_BASE) \
	&& echo "     Archive $(LEEC_RELEASE_ARCHIVE_XZ) ready in "`pwd`


# The '-L' option with cp is used so that symbolic links are replaced by their
# actual target file, otherwise tar would include dead links in releases.
#
prepare-release: clean clean-release
	@echo "     Preparing release archive for Leec $(LEEC_VERSION)"
	@cd .. && mkdir -p $(LEEC_RELEASE_BASE) && /bin/cp -L -r myriad leec $(LEEC_RELEASE_BASE)
	@cd ../$(LEEC_RELEASE_BASE) && mv leec/top-GNUmakefile-for-releases GNUmakefile
	-@cd .. && find $(LEEC_RELEASE_BASE) -type d -a -name '.git' -exec /bin/rm -rf '{}' ';' 2>/dev/null
	-@cd .. && find $(LEEC_RELEASE_BASE) -type f -a -name '*.beam' -exec /bin/rm -f '{}' ';' 2>/dev/null


clean: clean-release clean-archive


clean-release:
	@echo "   Cleaning release archive for Leec"
	-@cd .. && /bin/rm -rf $(LEEC_RELEASE_BASE)


clean-archive:
	-@cd .. && /bin/rm -f $(LEEC_RELEASES)


check-types:
	@$(REBAR3_EXEC) dialyzer


check-cross-references:
	@$(REBAR3_EXEC) xref


info-paths:
	@echo "BEAM_PATH_OPT = $(BEAM_PATH_OPT)"


info-compile:
	@echo "ERLANG_COMPILER_BASE_OPT = $(ERLANG_COMPILER_BASE_OPT)"
	@echo "BEAM_DIRS = $(BEAM_DIRS)"
	@echo "INC = $(INC)"
	@echo "ERLANG_COMPILER_EXEC_TARGET_OPT = $(ERLANG_COMPILER_EXEC_TARGET_OPT)"
	@echo "ERLANG_COMPILER_DEBUG_OPT = $(ERLANG_COMPILER_DEBUG_OPT)"
	@echo "ERLANG_COMPILER_NATIVE_COMPILATION_OPT = $(ERLANG_COMPILER_NATIVE_COMPILATION_OPT)"
	@echo "ERLANG_COMPILER_WARNING_OPT = $(ERLANG_COMPILER_WARNING_OPT)"
	@echo "ERLANG_COMPILER_OPT_BASE = $(ERLANG_COMPILER_OPT_BASE)"
	@echo "OVERALL_PZ_OPT = $(OVERALL_PZ_OPT)"
	@echo "ERLANG_COMPILER_OPT_FOR_STANDARD_MODULES = $(ERLANG_COMPILER_OPT_FOR_STANDARD_MODULES)"


include $(LEEC_TOP)/GNUmakesettings.inc
