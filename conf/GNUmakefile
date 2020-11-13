LEEC_TOP = ..


.PHONY: clean-local clean-rebar



# Typically to generate various flavours (normal, for Hex, for testing, etc.) of
# rebar.config files:
#
# (note: not centralised in a GNUmakerules-automatic file for all layers, as
# substitutions are layer-specific)
#
%: %.template $(LEEC_TOP)/GNUmakevars.inc
	@echo "  Generating $@ from $< (VERSION_FOR_REBAR3 being $(VERSION_FOR_REBAR3), TRACES_VERSION_FOR_REBAR being $(TRACES_VERSION), WOOPER_VERSION_FOR_REBAR being $(WOOPER_VERSION), MYRIAD_VERSION_FOR_REBAR being $(MYRIAD_VERSION)); this file should be copied to the root of this layer in order to be taken into account."
	@cat $< | sed "s|\"MYRIAD_VERSION_FOR_REBAR\"|\"$(MYRIAD_VERSION)\"|g" | sed "s|\"WOOPER_VERSION_FOR_REBAR\"|\"$(WOOPER_VERSION)\"|g" | sed "s|\"TRACES_VERSION_FOR_REBAR\"|\"$(TRACES_VERSION)\"|g" | sed "s|\"VERSION_FOR_REBAR3\"|\"$(VERSION_FOR_REBAR3)\"|g" | sed "s|FIRST_FILES_FOR_REBAR|$(REBAR_FIRST_FILES)|g" | sed "s|DEBUG_KEY_FOR_REBAR|$(DEBUG_INFO_KEY)|g"| sed "s|INCS_FOR_REBAR|$(REBAR_INCS)|g" > $@


clean: clean-local


clean-local: clean-rebar
	-@/bin/rm -f $(REBAR_CONF_FILES)


# Removed: -@/bin/rm -rf priv/
clean-rebar:
	-@/bin/rm -f rebar.config


include $(LEEC_TOP)/GNUmakesettings.inc
