LEEC_TOP = .


.PHONY: all all-rebar3 help  help-leec                                   \
		all register-version-in-header register-leec test-leec           \
		list-beam-dirs add-prerequisite-plts link-plt                    \
		send-release release release-zip release-bz2 release-xz          \
		prepare-release clean-release clean-archive                      \
		check-types check-cross-references                               \
		info-paths info-conditionals                                     \
		info-context info-versions info-deps


MODULES_DIRS = src doc test #priv


# To override the 'all' default target with a parallel version:
BASE_MAKEFILE = true


LEEC_RELEASES = $(LEEC_RELEASE_ARCHIVE_BZ2) \
				$(LEEC_RELEASE_ARCHIVE_ZIP) \
				$(LEEC_RELEASE_ARCHIVE_XZ)


# Now the default build system is our own. Use the 'all-rebar3' target if
# preferring the rebar3 way of building.
#
all:


all-rebar3:
	@$(MYRIAD_REBAR_EXEC) upgrade --all
	@$(MYRIAD_REBAR_EXEC) compile


# First target for default:
help: help-intro help-leec


help-leec:
	@cd $(MYRIAD_TOP) && $(MAKE) -s help-myriad


register-version-in-header:
	@if [ -z "$(VERSION_FILE)" ]; then \
	echo "Error, no version file defined." 1>&2; exit 51; else \
	$(MAKE) register-leec; fi


register-leec:
	@echo "-define( leec_version, \"$(LEEC_VERSION)\" )." >> $(VERSION_FILE)


# Maybe one day:
#test-leec:
#	@bin/eleec --config etc/leec-test.yml


# Useful to extract internal layout for re-use in upper layers:
list-beam-dirs:
	@for d in $(LEEC_BEAM_DIRS); do echo $$(readlink -f $$d); done


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
	@$(MYRIAD_REBAR_EXEC) dialyzer


check-cross-references:
	@$(MYRIAD_REBAR_EXEC) xref


info-conditionals:
	@echo "LEEC_DEBUG_FLAGS = $(LEEC_DEBUG_FLAGS)"
	@echo "LEEC_CHECK_FLAGS = $(LEEC_CHECK_FLAGS)"



# Typically useful to know the software context for continuous integration:
info-context: info-platform info-versions info-source-layout


info-versions:
	@echo "MYRIAD_VERSION    = $(MYRIAD_VERSION)"


info-deps:
	@echo "COWLIB_TOP = $(COWLIB_TOP) (i.e. $$(realpath $(COWLIB_TOP)))"
	@echo "GUN_TOP = $(GUN_TOP) (i.e. $$(realpath $(GUN_TOP)))"
	@echo "USE_SHOTGUN = $(USE_SHOTGUN) (i.e. $$(realpath $(USE_SHOTGUN)))"
	@echo "HTTPC_OPT = $(HTTPC_OPT) (i.e. $$(realpath $(HTTPC_OPT)))"
	@echo "SHOTGUN_TOP = $(SHOTGUN_TOP) (i.e. $$(realpath $(SHOTGUN_TOP)))"
	@echo "ELLI_TOP = $(ELLI_TOP) (i.e. $$(realpath $(ELLI_TOP)))"
	@echo "ERLANG_COLOR_TOP = $(ERLANG_COLOR_TOP) (i.e. $$(realpath $(ERLANG_COLOR_TOP)))"
	@echo "YAMERL_TOP = $(YAMERL_TOP) (i.e. $$(realpath $(YAMERL_TOP)))"
	@echo "GETOPT_TOP = $(GETOPT_TOP) (i.e. $$(realpath $(GETOPT_TOP)))"
	@echo "JSX_TOP = $(JSX_TOP) (i.e. $$(realpath $(JSX_TOP)))"
	@echo "JIFFY_TOP = $(JIFFY_TOP) (i.e. $$(realpath $(JIFFY_TOP)))"


include $(LEEC_TOP)/GNUmakesettings.inc
