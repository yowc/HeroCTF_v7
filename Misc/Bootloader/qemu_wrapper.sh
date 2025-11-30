#!/bin/sh
set -e

# Ce script est exécuté pour chaque connexion nc.
# Son stdin/stdout sont directement reliés au client via socat.

echo "Press ENTER to start boot"

# On attend que le joueur appuie sur ENTER (lecture d'une ligne)
# Tant qu'il n'envoie pas de '\n', on ne lance pas QEMU.
read _

# Une fois ENTER reçu, on remplace le script par QEMU
# exec => QEMU récupère le même stdin/stdout (la même connexion TCP).
exec qemu-system-arm -machine virt -nographic \
  -bios /challenge/u-boot.bin \
  -device loader,file=/challenge/firmware.bin,addr=0x40200000
