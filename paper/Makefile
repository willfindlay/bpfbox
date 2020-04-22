# ============================ #
# =======   Files      ======= #
# ============================ #

TEX    = paper.tex
FIGS   =
BIB    =
TABLES =

PDF = $(TEX:.tex=.pdf)

# ============================ #
# =======   Options    ======= #
# ============================ #

# latexmk flags
LATEXMK_FLAGS = -pdf

# ============================ #
# =======   Rules      ======= #
# ============================ #

.PHONY: all
all: $(PDF)

$(PDF): $(TEX) $(BIB) $(FIGS) $(TABLES)
	latexmk $(LATEXMK_FLAGS) $(TEX)

.PHONY: proper
proper:
	latexmk -c

.PHONY: clean
clean:
	latexmk -C
