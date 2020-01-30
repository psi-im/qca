/*
 * Copyright (C) 2007  Alon Bar-Lev <alon.barlev@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 */

#include <QtCrypto>
#include <qcaprovider.h>
#include <QtPlugin>
#include <QTextStream>
#include <QFile>

#include <stdlib.h>

using namespace QCA;

namespace loggerQCAPlugin {

class StreamLogger : public QCA::AbstractLogDevice
{
    Q_OBJECT
public:
	StreamLogger(QTextStream &stream) : QCA::AbstractLogDevice( "Stream logger" ), _stream(stream)
	{
		QCA::logger()->registerLogDevice (this);
	}

	~StreamLogger() override
	{
		QCA::logger()->unregisterLogDevice (name ());
	}

	void logTextMessage( const QString &message, enum QCA::Logger::Severity severity ) override
	{
		_stream << now () << " " << severityName (severity) << " " << message << endl;
	}

	void logBinaryMessage( const QByteArray &blob, enum QCA::Logger::Severity severity ) override
	{
		Q_UNUSED(blob);
		_stream << now () << " " << severityName (severity) << " " << "Binary blob not implemented yet" << endl;
	}

private:
	inline const char *severityName( enum QCA::Logger::Severity severity )
	{
		if (severity <= QCA::Logger::Debug) {
			return s_severityNames[severity];
		}
		else {
			return s_severityNames[QCA::Logger::Debug+1];
		}
	}

	inline QString now() {
		static const QString format = "yyyy-MM-dd hh:mm:ss";
		return QDateTime::currentDateTime ().toString (format);
	}

private:
	static const char *s_severityNames[];
	QTextStream &_stream;
};

const char *StreamLogger::s_severityNames[] = {
	"Q",
	"M",
	"A",
	"C",
	"E",
	"W",
	"N",
	"I",
	"D",
	"U"
};

}

using namespace loggerQCAPlugin;

class loggerProvider : public Provider
{
private:
	QFile _logFile;
	QTextStream _logStream;
	StreamLogger *_streamLogger;
	bool _externalConfig;

public:
	loggerProvider () {
		_externalConfig = false;
		_streamLogger = NULL;

		QByteArray level = qgetenv ("QCALOGGER_LEVEL");
		QByteArray file = qgetenv ("QCALOGGER_FILE");

		if (!level.isEmpty ()) {
			printf ("XXXX %s %s\n", level.data (), file.data ());
			_externalConfig = true;
			createLogger (
				atoi (level.constData()),
				file.isEmpty () ? QString() : QString::fromUtf8 (file)
			);
		}
	}

	~loggerProvider () override {
		delete _streamLogger;
		_streamLogger = NULL;
	}

public:
	int
	qcaVersion() const override {
		return QCA_VERSION;
	}

	void
	init () override {}

	QString
	name () const override {
		return "qca-logger";
	}

	QStringList
	features () const override {
		QStringList list;
		list += "log";
		return list;
	}

	Context *
	createContext (
		const QString &type
	) override {
		Q_UNUSED(type);
		return NULL;
	}

	QVariantMap
	defaultConfig () const override {
		QVariantMap mytemplate;

		mytemplate["formtype"] = "http://affinix.com/qca/forms/qca-logger#1.0";
		mytemplate["enabled"] = false;
		mytemplate["file"] = "";
		mytemplate["level"] = (int)Logger::Quiet;

		return mytemplate;
	}

	void
	configChanged (const QVariantMap &config) override {
		if (!_externalConfig) {
			delete _streamLogger;
			_streamLogger = NULL;

			if (config["enabled"].toBool ()) {
				createLogger (
					config["level"].toInt (),
					config["file"].toString ()
				);
			}
		}
	}

private:
	void
	createLogger (
		const int level,
		const QString &file
	) {
		bool success = false;
		if (file.isEmpty ()) {
			success = _logFile.open (stderr, QIODevice::WriteOnly | QIODevice::Text | QIODevice::Unbuffered);
		}
		else {
			_logFile.setFileName (file);
			success = _logFile.open (QIODevice::Append | QIODevice::Text | QIODevice::Unbuffered);
		}

		if (success) {
			_logStream.setDevice (&_logFile);
			logger ()->setLevel ((Logger::Severity)level);
			_streamLogger = new StreamLogger (_logStream);
		}
	}
};

class loggerPlugin : public QObject, public QCAPlugin
{
	Q_OBJECT
	Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
	Q_INTERFACES(QCAPlugin)

public:
	Provider *createProvider() override { return new loggerProvider; }
};

#include "qca-logger.moc"

