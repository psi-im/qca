/*
 * qca_securefile.h - secure file I/O
 * Copyright (C) 2026  Sergei Ilinykh <rion4ik@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef QCA_SECUREFILE_H
#define QCA_SECUREFILE_H

#include "qca_export.h"
#include "qca_tools.h"

#include <QScopedPointer>
#include <QString>

namespace QCA {

/**
   \class SecureFile qca_securefile.h QtCrypto

   Read and write secret file contents without copying them through
   ordinary QByteArray storage.

   SecureFile only accepts regular files. Symbolic links and other
   indirections are rejected. Writes use a private temporary file in the
   destination directory and atomically replace the destination after the
   data has been flushed.

   The returned SecureArray is empty both for an empty file and after a
   failed read. Check error() to distinguish these cases.

   SecureFile protects secret material while it is being transferred to and
   from the filesystem. It does not encrypt file contents at rest.

   \ingroup UserAPI
*/
class QCA_EXPORT SecureFile
{
public:
    /** Maximum file size used unless changed with setMaximumSize(). */
    static constexpr qint64 DefaultMaximumSize = 16 * 1024 * 1024;

    /** Error reported by the last operation. */
    enum Error
    {
        NoError,
        InvalidPath,
        OpenError,
        InvalidFile,
        TooLarge,
        ReadError,
        WriteError,
        CommitError
    };

    /** Construct a secure file object for \a fileName. */
    explicit SecureFile(const QString &fileName = QString());
    ~SecureFile();

    /** Change the file operated on by this object. */
    void setFileName(const QString &fileName);

    /** Return the current file name. */
    QString fileName() const;

    /**
       Set the largest file accepted by read() or write().

       Negative sizes are treated as zero. The implementation is also
       limited by SecureArray's maximum representable size.
    */
    void setMaximumSize(qint64 bytes);

    /** Return the configured maximum file size. */
    qint64 maximumSize() const;

    /**
       Read the complete regular file directly into secure memory.

       On failure an empty SecureArray is returned and error() describes the
       failure.
    */
    SecureArray read();

    /**
       Atomically replace the file with \a data.

       Secret bytes are written directly from SecureArray storage. On Unix,
       newly written files are created with mode 0600.
    */
    bool write(const SecureArray &data);

    /** Return the error from the last read() or write(). */
    Error error() const;

    /** Return a human readable description of the last error. */
    QString errorString() const;

private:
    Q_DISABLE_COPY(SecureFile)

    class Private;
    QScopedPointer<Private> d;
};

} // namespace QCA

#endif
