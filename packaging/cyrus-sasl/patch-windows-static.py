#!/usr/bin/env python3
from pathlib import Path
import re
import sys

root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
libmk = root / 'lib' / 'NTMakefile'
md5global = root / 'include' / 'md5global.h'


def remove_unused_windows_md5_typedefs() -> None:
    # Cyrus' generated md5global.h names types by byte width, so INT8/UINT8
    # are 64-bit there. Modern Windows SDK headers use the same names for
    # 8-bit types. The 64-bit aliases are unused by Cyrus 2.1.28; remove only
    # those two generated typedefs and fail if that assumption ever changes.
    tokens = ('INT8', 'UINT8')
    source_suffixes = {'.c', '.h'}
    compiled_roots = (
        root / 'lib',
        root / 'common',
        root / 'include',
        root / 'win32' / 'include',
    )
    selected_plugins = (
        root / 'plugins' / 'plain.c',
        root / 'plugins' / 'scram.c',
        root / 'plugins' / 'digestmd5.c',
    )
    source_files = list(selected_plugins)
    for source_root in compiled_roots:
        if source_root.exists():
            source_files.extend(
                path
                for path in source_root.rglob('*')
                if path.is_file() and path.suffix.lower() in source_suffixes
            )

    for token in tokens:
        pattern = re.compile(rf'\b{token}\b')
        users = []
        for path in source_files:
            if path == md5global or not path.exists():
                continue
            try:
                text = path.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                text = path.read_text(encoding='latin-1')
            if pattern.search(text):
                users.append(path.relative_to(root))
        if users:
            joined = ', '.join(map(str, users[:8]))
            raise SystemExit(f'{token} is used by the Windows static build: {joined}')

    text = md5global.read_text(encoding='utf-8')
    for token in tokens:
        pattern = re.compile(rf'^typedef[^;\n]*\b{token};[^\n]*(?:\n|$)', re.MULTILINE)
        text, count = pattern.subn('', text, count=1)
        if count != 1:
            raise SystemExit(f'{md5global}: expected exactly one typedef for {token}, found {count}')
    md5global.write_text(text, encoding='utf-8')


remove_unused_windows_md5_typedefs()


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding='utf-8')
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{path}: expected exactly one match, found {count}: {old!r}')
    path.write_text(text.replace(old, new), encoding='utf-8')

replace_once(
    libmk,
    'libsasl_res = libsasl.res\n'
    'libsasl_out = libsasl.dll libsasl.exp libsasl.lib $(libsasl_res)\n',
    'libsasl_res = libsasl.res\n'
    '\n'
    '!IF "$(STATIC_BUNDLE)" == "1"\n'
    'static_plugin_objs = plain.obj scram.obj digestmd5.obj\n'
    'libsasl_out = libsasl2-static.lib\n'
    'STATIC_PLUGIN_FLAGS = /D "STATIC_PLAIN" /D "STATIC_SCRAM" /D "STATIC_DIGESTMD5" /D "HAVE_SHA512=1"\n'
    '!ELSE\n'
    'static_plugin_objs =\n'
    'libsasl_out = libsasl.dll libsasl.exp libsasl.lib $(libsasl_res)\n'
    'STATIC_PLUGIN_FLAGS =\n'
    '!ENDIF\n'
)

replace_once(
    libmk,
    'CPPFLAGS = /wd4996 /D NEED_GETOPT /I "..\\win32\\include" /I "." /I "..\\include" /D "LIBSASL_EXPORTS" $(COMMON_CPPFLAGS)\n',
    'CPPFLAGS = /wd4996 /D NEED_GETOPT /I "..\\win32\\include" /I "." /I "..\\include" /I "..\\plugins" /I "..\\common" /I "$(OPENSSL_INCLUDE)" /D "LIBSASL_EXPORTS" $(STATIC_PLUGIN_FLAGS) $(COMMON_CPPFLAGS)\n'
)

replace_once(
    libmk,
    'all_objs = $(libsasl_objs)\n',
    'all_objs = $(libsasl_objs) $(static_plugin_objs)\n'
)

replace_once(
    libmk,
    'install: libsasl.dll\n'
    '\t@echo libsasl.exp > $(exclude_list)\n',
    '!IF "$(STATIC_BUNDLE)" == "1"\n'
    'install: libsasl2-static.lib\n'
    '\t@if not exist "$(libdir)" mkdir "$(libdir)"\n'
    '\t@copy /Y libsasl2-static.lib "$(libdir)\\libsasl2-static.lib"\n'
    '!ELSE\n'
    'install: libsasl.dll\n'
    '\t@echo libsasl.exp > $(exclude_list)\n'
)

replace_once(
    libmk,
    '\t@xcopy libsasl.l* "$(libdir)" /I /F /Y\n\n'
    'all-recursive: libsasl.dll\n\n'
    'libsasl.dll: $(libsasl_objs) $(libsasl_res)\n',
    '\t@xcopy libsasl.l* "$(libdir)" /I /F /Y\n'
    '!ENDIF\n\n'
    '!IF "$(STATIC_BUNDLE)" == "1"\n'
    'all-recursive: libsasl2-static.lib\n\n'
    'libsasl2-static.lib: $(all_objs)\n'
    '\tlib /NOLOGO /OUT:"libsasl2-static.lib" $(all_objs)\n'
    '!ELSE\n'
    'all-recursive: libsasl.dll\n\n'
    'libsasl.dll: $(libsasl_objs) $(libsasl_res)\n'
)

replace_once(
    libmk,
    '\tIF EXIST $@.manifest mt -manifest $@.manifest -outputresource:$@;2\n\n'
    'plugin_common.c:',
    '\tIF EXIST $@.manifest mt -manifest $@.manifest -outputresource:$@;2\n'
    '!ENDIF\n\n'
    'plugin_common.c:'
)

replace_once(
    libmk,
    '.c.obj::\n'
    '   $(CPP) @<<\n'
    '   $(CPP_PROJ) $< \n'
    '<<\n',
    '.c.obj::\n'
    '   $(CPP) @<<\n'
    '   $(CPP_PROJ) $< \n'
    '<<\n'
    '\n'
    '{..\\plugins}.c.obj::\n'
    '   $(CPP) @<<\n'
    '   $(CPP_PROJ) $<\n'
    '<<\n'
)

print(f'Patched {libmk}')
