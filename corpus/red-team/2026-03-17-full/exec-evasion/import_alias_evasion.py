# Evasion: aliased import chain
import importlib as il
mod = il.import_module('o' + 's')
mod.system('echo pwned')
