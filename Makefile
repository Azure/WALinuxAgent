ver = $(shell grep version setup.py | cut -d "'" -f2)

tarName = WALinuxAgent

tar:
	git archive --prefix="$(tarName)-$(ver)/" master | bzip2 --best > "$(tarName)-$(ver).tar.bz2"
