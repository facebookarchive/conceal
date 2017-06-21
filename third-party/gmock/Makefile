LATEST_TAG := release-1.8.0
REPO_URL := https://github.com/google/googletest.git
SRC_DIR := googletest-1.8.0 

.PHONY: all
all: clone 

.PHONY: clone
clone:
	-git clone -b $(LATEST_TAG) --single-branch $(REPO_URL) $(SRC_DIR)

.PHONY: clean
clean:
	-rm -rf $(SRC_DIR)
