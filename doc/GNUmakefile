LEEC_TOP = ..


DOC_BASE_NAME := Ceylan-LEEC-technical-manual-english


OVERALL_DOCUMENT_SOURCE := $(DOC_BASE_NAME).rst


CURRENT_LEEC_HTML := $(DOC_BASE_NAME).html

HTML_TARGET := $(CURRENT_LEEC_HTML)


CURRENT_LEEC_PDF := $(DOC_BASE_NAME).pdf

PDF_TARGET := $(CURRENT_LEEC_PDF)


DOC_GENERATED_FILES := $(HTML_TARGET) $(PDF_TARGET)



PROJECT_CSS := pygments-default.css,leec.css

PROJECT_ICON := leec-icon.png

WEB_CONTENT = *.html *.css *.png *.pdf

# Read from the user's environment:
GITHUB_PAGES_BASE := $(shell basename "$(LEEC_WEB_MIRROR_BRANCH)")




.PHONY: doc all full-doc html pdf clone-mirror           \
		export-doc export-to-official export-to-mirror   \
		clean clean-doc clean-links info info-web



# Default do-nothing target:
doc:


all:
	@echo "  Run 'make full-doc' to generate the manual of the 'LEEC' layer."



full-doc: $(DOC_GENERATED_FILES)
	@/bin/ln -sf $(CURRENT_LEEC_HTML) leec.html
	@/bin/ln -sf leec.html index.html
	@/bin/ln -sf $(CURRENT_LEEC_PDF) leec.pdf


html: clean-doc $(HTML_TARGET)

pdf: clean-doc $(PDF_TARGET)


# Creates a separate repository for the GitHub pages branch:
# (please then remove all initial content of that branch)
#
clone-mirror:
	@cd ../../ && git clone https://github.com/Olivier-Boudeville/letsencrypt-erlang $(GITHUB_PAGES_BASE) && cd $(GITHUB_PAGES_BASE) && git checkout -b gh-pages


export-doc: clean-doc full-doc export-to-official export-to-mirror


# Drawback: scp will not preserve symlinks, it will duplicate files instead.
#
# rsync would not, but requires a different source layout (copies a full tree,
# not a set of files), so currently not used:
# rsync -avze "ssh $(SP)" $(SOME_WEB_TREE) $(WEB_SRV):$(WEB_ROOT)/LEEC/
#
export-to-official: $(DOC_GENERATED_FILES)
	@echo "   Exporting LEEC documentation to official website"
	@/bin/scp $(SP) $(WEB_CONTENT) $(WEB_SRV):$(WEB_ROOT)/LEEC/


export-to-mirror: $(DOC_GENERATED_FILES)
	@echo "   Exporting LEEC documentation to mirror website in $(LEEC_WEB_MIRROR_BRANCH)"
	@/bin/cp -f $(WEB_CONTENT) $(LEEC_WEB_MIRROR_BRANCH) && cd $(LEEC_WEB_MIRROR_BRANCH) && git add . && git merge -s ours && git commit -m "LEEC doc updated." && git push && git pull --ff-only



clean: clean-doc


clean-doc: clean-links
	@echo "     Cleaning documentation"
	-@/bin/rm -f *.aux *.log *.maf *.mtc* *.stc* *.tex *.toc $(DOC_GENERATED_FILES)


clean-links:
	-@/bin/rm -f index.html


info: info-doc info-web

info-doc:
	@echo "OVERALL_DOCUMENT_SOURCE = $(OVERALL_DOCUMENT_SOURCE)"
	@echo "DOC_TRACKER = $(DOC_TRACKER)"


info-web:
	@echo "HTML_TARGET = $(HTML_TARGET)"
	@echo "SP = $(SP)"
	@echo "WEB_CONTENT = $(WEB_CONTENT)"
	@echo "WEB_SRV = $(WEB_SRV)"
	@echo "WEB_ROOT = $(WEB_ROOT)"
	@echo "LEEC_WEB_MIRROR_BRANCH = $(LEEC_WEB_MIRROR_BRANCH)"
	@echo "GITHUB_PAGES_BASE = $(GITHUB_PAGES_BASE)"


DOCUTILS_TOP = .

include $(LEEC_TOP)/GNUmakesettings.inc
