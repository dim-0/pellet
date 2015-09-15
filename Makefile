# Makefile for pellet

#### configuration begin ####

## package name and latest version ##
PACKAGE_NAME = pellet
PACKAGE_VERSION = $(lastword $(sort $(subst upstream/,, $(filter upstream/%, $(shell git tag)))))

## paths & directories ##
# pellet's config directory (where pellet.conf, main.cf and master.cf reside)
PELLET_ETC_DIR = /etc/pellet

# lib directory (where the script will go)
PELLET_LIB_DIR = /usr/lib/postfix

# directories for man pages section 3
MAN3DIR = /usr/share/man/man3

## users & ports
# pellet user (who will run the script)
PELLET_USER = pellet

# pellet group
PELLET_GROUP = pellet

# pellet port (where pellet accepts requests)
PELLET_PORT = 32776

## usually no need to configure anything below this line ##
# script #
SCRIPT = pellet.py.in
SCRIPT_TARGET = pellet.py

# manual pages in their respective sections #
MAN3PAGES = pellet.3.in
MAN3PAGES_TARGET = pellet.3

# sample config file
CONFIG = pellet.conf.dist.in
CONFIG_TARGET = pellet.conf.dist

#### configuration end ####

.PHONY: all build install install_man clean

all: build

build: ${SCRIPT_TARGET} ${MAN3PAGES_TARGET} ${CONFIG_TARGET}

${SCRIPT_TARGET}: ${SCRIPT}
	sed -e 's:PELLET_ETC_DIR:${PELLET_ETC_DIR}:g' \
	  -e 's:PELLET_LIB_DIR:${PELLET_LIB_DIR}:g' \
	  -e 's:PELLET_USER:${PELLET_USER}:g' \
	  -e 's:PELLET_PORT:${PELLET_PORT}:g' \
		-e 's:MAN3DIR:${MAN3DIR}:g' \
	$< > $@

${MAN3PAGES_TARGET}: ${MAN3PAGES}
	sed -e 's:PELLET_ETC_DIR:${PELLET_ETC_DIR}:g' \
	  -e 's:PELLET_LIB_DIR:${PELLET_LIB_DIR}:g' \
	  -e 's:PELLET_USER:${PELLET_USER}:g' \
	  -e 's:PELLET_PORT:${PELLET_PORT}:g' \
		-e 's:MAN3DIR:${MAN3DIR}:g' \
	$< > $@

${CONFIG_TARGET}: ${CONFIG}
	sed -e 's:PELLET_ETC_DIR:${PELLET_ETC_DIR}:g' \
	  -e 's:PELLET_LIB_DIR:${PELLET_LIB_DIR}:g' \
	  -e 's:PELLET_USER:${PELLET_USER}:g' \
	  -e 's:PELLET_PORT:${PELLET_PORT}:g' \
		-e 's:MAN3DIR:${MAN3DIR}:g' \
	$< > $@

install: install_script install_config install_man

install_script: ${SCRIPT_TARGET}
	install -d ${DESTDIR}/${PELLET_LIB_DIR}
	install -m 750 $< ${DESTDIR}/${PELLET_LIB_DIR}
	chown ${PELLET_USER}:${PELLET_GROUP} ${DESTDIR}/${PELLET_LIB_DIR}/${SCRIPT_TARGET}

install_man: ${MAN3PAGES_TARGET}
	install -d ${DESTDIR}/${MAN3DIR}
	install $? ${DESTDIR}/${MAN3DIR}

install_config: ${CONFIG_TARGET}
	install -d ${DESTDIR}/${PELLET_ETC_DIR}
	install -m 600 $< ${DESTDIR}/${PELLET_ETC_DIR}
	chown ${PELLET_USER}:${PELLET_GROUP} ${DESTDIR}/${PELLET_ETC_DIR}/${CONFIG_TARGET}

clean:
	$(RM) ${SCRIPT_TARGET} ${MAN1PAGES_TARGET} ${CONFIG_TARGET}

dist:
	git archive --format=tar --prefix ${PACKAGE_NAME}-${PACKAGE_VERSION}/ \
		upstream/${PACKAGE_VERSION} \
	| gzip -9f > ${PACKAGE_NAME}-${PACKAGE_VERSION}.tar.gz
#EOF
