/**
 * NetworkProtocolTCPS
 *
 * TCP over TLS Protocol Adapter Implementation
 */

#include "TCPS.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include "compat_inet.h"

#include "../../include/debug.h"

#include "status_error_codes.h"

#include <vector>

/**
 * @brief ctor
 * @param rx_buf pointer to receive buffer
 * @param tx_buf pointer to transmit buffer
 * @param sp_buf pointer to special buffer
 * @return a NetworkProtocolTCPS object
 */
NetworkProtocolTCPS::NetworkProtocolTCPS(std::string *rx_buf, std::string *tx_buf,
                                         std::string *sp_buf)
    : NetworkProtocol(rx_buf, tx_buf, sp_buf)
{
    Debug_printf("NetworkProtocolTCPS::ctor\r\n");
}

/**
 * dtor
 */
NetworkProtocolTCPS::~NetworkProtocolTCPS()
{
    Debug_printf("NetworkProtocolTCPS::dtor\r\n");
    tcp_tls_conn.stop();
}

/**
 * @brief Open connection to the protocol using URL
 * @param urlParser The URL object passed in to open.
 * @param cmdFrame The command frame to extract aux1/aux2/etc.
 */
protocolError_t NetworkProtocolTCPS::open(PeoplesUrlParser *urlParser, fileAccessMode_t access,
                                          netProtoTranslation_t translate)
{
    protocolError_t ret = PROTOCOL_ERROR::UNSPECIFIED; // assume error until proven ok

    Debug_printf("NetworkProtocolTCPS::open(%s:%s)\r\n", urlParser->host.c_str(),
                 urlParser->port.c_str());

    if (urlParser->host.empty())
    {
        // Open server on port, otherwise, treat as empty socket.
        if (!urlParser->port.empty())
            ret = open_server(urlParser->getPort());
        else
        {
            ret = PROTOCOL_ERROR::NONE; // No error.
        }
    }
    else
    {
        if (urlParser->port.empty())
            urlParser->port = "23";

        // open client connection
        ret = open_client(urlParser->host, urlParser->getPort());
    }

    // call base class
    NetworkProtocol::open(urlParser, access, translate);

    return ret;
}

/**
 * @brief Close connection to the protocol.
 */
protocolError_t NetworkProtocolTCPS::close()
{
    Debug_printf("NetworkProtocolTCPS::close()\r\n");
    NetworkProtocol::close();
    tcp_tls_conn.stop();
    return PROTOCOL_ERROR::NONE;
}

/**
 * @brief Read len bytes into rx_buf, If protocol times out, the buffer should be null padded
 * to length.
 * @param len number of bytes to read.
 * @return PROTOCOL_ERROR::NONE on success, PROTOCOL_ERROR::UNSPECIFIED on error
 */
protocolError_t NetworkProtocolTCPS::read(unsigned short len)
{
    unsigned short actual_len = 0;
    std::vector<uint8_t> newData = std::vector<uint8_t>(len);

    Debug_printf("NetworkProtocolTCPS::read(%u)\r\n", len);

    if (receiveBuffer->length() == 0)
    {
        // Do the read from client socket.
        actual_len = tcp_tls_conn.read(newData.data(), len);

        // bail if the connection is reset.
        if (errno == ECONNRESET)
        {
            error = NDEV_STATUS::CONNECTION_RESET;
            return PROTOCOL_ERROR::UNSPECIFIED;
        }
        else if (actual_len != len) // Read was short and timed out.
        {
            error = NDEV_STATUS::SOCKET_TIMEOUT;
            return PROTOCOL_ERROR::UNSPECIFIED;
        }

        // Add new data to buffer.
        receiveBuffer->insert(receiveBuffer->end(), newData.begin(), newData.end());
    }
    error = NDEV_STATUS::SUCCESS;
    return NetworkProtocol::read(len);
}

/**
 * @brief Write len bytes from tx_buf to protocol.
 * @param len The # of bytes to transmit, len should not be larger than buffer.
 * @return Number of bytes written.
 */
protocolError_t NetworkProtocolTCPS::write(unsigned short len)
{
    int actual_len = 0;

    Debug_printf("NetworkProtocolTCPS::write(%u)\r\n", len);

    // Check for client connection
    if (!tcp_tls_conn.connected())
    {
        error = NDEV_STATUS::NOT_CONNECTED;
        return PROTOCOL_ERROR::UNSPECIFIED; // error
    }

    // Call base class to do translation.
    len = translate_transmit_buffer();

    // Do the write to client socket.
    actual_len = tcp_tls_conn.write((uint8_t *)transmitBuffer->data(), len);

    // bail if the connection is reset.
    if (errno == ECONNRESET)
    {
        error = NDEV_STATUS::CONNECTION_RESET;
        return PROTOCOL_ERROR::UNSPECIFIED;
    }
    else if (actual_len != len) // write was short.
    {
        Debug_printf("NetworkProtocolTCPS: Short send. We sent %u bytes, but asked to send %u "
                     "bytes.\r\n",
                     actual_len, len);
        error = NDEV_STATUS::SOCKET_TIMEOUT;
        return PROTOCOL_ERROR::UNSPECIFIED;
    }

    // Return success
    error = NDEV_STATUS::SOCKET_TIMEOUT;
    transmitBuffer->erase(0, len);

    return PROTOCOL_ERROR::NONE;
}

/**
 * @brief Return protocol status information in provided NetworkStatus object.
 * @param status a pointer to a NetworkStatus object to receive status information
 * @return PROTOCOL_ERROR::NONE on success, PROTOCOL_ERROR::UNSPECIFIED on error
 */
protocolError_t NetworkProtocolTCPS::status(NetworkStatus *status)
{
    if (connectionIsServer == true)
        status_server(status);
    else
        status_client(status);

    NetworkProtocol::status(status);

    return PROTOCOL_ERROR::NONE;
}

void NetworkProtocolTCPS::status_client(NetworkStatus *status)
{
    status->connected = tcp_tls_conn.connected();
    status->error = tcp_tls_conn.connected() ? error : NDEV_STATUS::END_OF_FILE;
}

void NetworkProtocolTCPS::status_server(NetworkStatus *status)
{
    if (tcp_tls_conn.connected())
        status_client(status);
    else
    {
        status->connected = tcp_tls_conn.hasClient();
        status->error = error;
    }
}

size_t NetworkProtocolTCPS::available()
{
    if (!tcp_tls_conn.connected())
        return 0;
    size_t avail = receiveBuffer->size();
    if (!avail)
        avail = tcp_tls_conn.available();
    return avail;
}

/**
 * Open a server (listening) connection.
 * @param port bind to port #
 * @return PROTOCOL_ERROR::NONE on success, PROTOCOL_ERROR::UNSPECIFIED on error
 */
protocolError_t NetworkProtocolTCPS::open_server(unsigned short port)
{
    Debug_printf("NetworkProtocolTCPS: Binding to port %d\r\n", port);

    // server = new fnTcpsConnection((uint16_t)port);
    int res = tcp_tls_conn.begin_listening((uint16_t)port);
    connectionIsServer = true; // set even if we're in error
    if (res == 0)
    {
        Debug_printf("NetworkProtocolTCPS: errno = %u\r\n", errno);
        errno_to_error();
        return PROTOCOL_ERROR::UNSPECIFIED;
    }

    return PROTOCOL_ERROR::NONE;
}

/**
 * Open a client connection to host and port.
 * @param hostname The hostname to connect to.
 * @param port the port number to connect to.
 * @return PROTOCOL_ERROR::NONE on success, PROTOCOL_ERROR::UNSPECIFIED on error
 */
protocolError_t NetworkProtocolTCPS::open_client(std::string hostname, unsigned short port)
{
    int res = 0;

    connectionIsServer = false;

    Debug_printf("Connecting to host %s port %d\r\n", hostname.c_str(), port);

#ifdef ESP_PLATFORM
    res = tcp_tls_conn.connect(hostname.c_str(), port);
#else
    res = tcp_tls_conn.connect(hostname.c_str(), port,
                               5000); // TODO constant for connect timeout
#endif

    if (res == 0)
    {
        errno_to_error();
        return PROTOCOL_ERROR::UNSPECIFIED; // Error.
    }
    else
        return PROTOCOL_ERROR::NONE; // We're connected.
}

/**
 * Special: Accept a server connection, transfer to client socket.
 */
protocolError_t NetworkProtocolTCPS::special_accept_connection()
{
    if (!tcp_tls_conn.hasClient())
    {
        Debug_printf("NetworkProtocolTCPS: Attempted accept without a client connection.\r\n");
        error = NDEV_STATUS::SERVER_NOT_RUNNING;
        return PROTOCOL_ERROR::UNSPECIFIED; // Error
    }

    int res = 1;

    if (tcp_tls_conn.hasClient())
    {
        in_addr_t remoteIP;
        unsigned char remotePort;
        char *remoteIPString;

        remoteIP = tcp_tls_conn.remoteIP();
        remotePort = tcp_tls_conn.remotePort();
        remoteIPString = compat_inet_ntoa(remoteIP);
        res = tcp_tls_conn.accept_connection();
        if (res == 0)
        {
            Debug_printf("NetworkProtocolTCPS: Accepted connection from %s:%u\r\n",
                         remoteIPString, remotePort);
            return PROTOCOL_ERROR::NONE;
        }
        else
        {
            return PROTOCOL_ERROR::UNSPECIFIED;
        }
    }
    else
    {
        error = NDEV_STATUS::CONNECTION_RESET;
        Debug_printf("NetworkProtocolTCPS: Client immediately disconnected.\r\n");
        return PROTOCOL_ERROR::UNSPECIFIED;
    }
}

/**
 * Special: Close connection .
 */
protocolError_t NetworkProtocolTCPS::special_close_client_connection()
{
    tcp_tls_conn.stop();

    // Clear all buffers.
    receiveBuffer->clear();
    transmitBuffer->clear();
    specialBuffer->clear();

    return PROTOCOL_ERROR::UNSPECIFIED;
}
