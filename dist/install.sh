#!/bin/sh
cd "$(dirname -- "$0")" || exit 1

install -vDm0755 "bin/fortify" "${FORTIFY_INSTALL_PREFIX}/usr/bin/fortify"
install -vDm0755 "bin/fpkg" "${FORTIFY_INSTALL_PREFIX}/usr/bin/fpkg"

install -vDm6511 "bin/fsu" "${FORTIFY_INSTALL_PREFIX}/usr/bin/fsu"
if [ ! -f "${FORTIFY_INSTALL_PREFIX}/etc/fsurc" ]; then
    install -vDm0400 "fsurc.default" "${FORTIFY_INSTALL_PREFIX}/etc/fsurc"
fi

install -vDm0644 "comp/_fortify" "${FORTIFY_INSTALL_PREFIX}/usr/share/zsh/site-functions/_fortify"