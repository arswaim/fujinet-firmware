/**
 * Network Protocol implementation for TCP sockets over TLS
 */

#ifndef NETWORKPROTOCOL_TCPS
#define NETWORKPROTOCOL_TCPS

#include "Protocol.h"
#include "fnTcpsConnection.h"

class NetworkProtocolTCPS : public NetworkProtocol
{
public:
    /**
     * ctor
     */
    NetworkProtocolTCPS(std::string *rx_buf, std::string *tx_buf, std::string *sp_buf);

    /**
     * dtor
     */
    virtual ~NetworkProtocolTCPS();

    /**
     * @brief Open connection to the protocol using URL
     * @param urlParser The URL object passed in to open.
     * @param cmdFrame The command frame to extract aux1/aux2/etc.
     * @return NETPROTO_ERR_NONE on success, NETPROTO_ERR_UNSPECIFIED on error
     */
    protocolError_t open(PeoplesUrlParser *urlParser, fileAccessMode_t access,
                         netProtoTranslation_t translate) override;

    /**
     * @brief Close connection to the protocol.
     */
    protocolError_t close() override;

    /**
     * @brief Read len bytes into rx_buf, If protocol times out, the buffer should be null
     * padded to length.
     * @param len Number of bytes to read.
     * @return NETPROTO_ERR_NONE on success, NETPROTO_ERR_UNSPECIFIED on error
     */
    protocolError_t read(unsigned short len) override;

    /**
     * @brief Write len bytes from tx_buf to protocol.
     * @param len The # of bytes to transmit, len should not be larger than buffer.
     * @return NETPROTO_ERR_NONE on success, NETPROTO_ERR_UNSPECIFIED on error
     */
    protocolError_t write(unsigned short len) override;

    /**
     * @brief Return protocol status information in provided NetworkStatus object.
     * @param status a pointer to a NetworkStatus object to receive status information
     * @return NETPROTO_ERR_NONE on success, NETPROTO_ERR_UNSPECIFIED on error
     */
    protocolError_t status(NetworkStatus *status) override;

protected:
    /**
     * a fnTcpsConnection object representing a TCP connection using TLS.
     */
    fnTcpsConnection tcp_tls_conn;

    /**
     * Open a server (listening) connection.
     * @param port bind to port #
     * @return NETPROTO_ERR_NONE on success, NETPROTO_ERR_UNSPECIFIED on error
     */
    protocolError_t open_server(unsigned short port);

    /**
     * Open a client connection to host and port.
     * @param hostname The hostname to connect to.
     * @param port the port number to connect to.
     * @return NETPROTO_ERR_NONE on success, NETPROTO_ERR_UNSPECIFIED on error
     */
    protocolError_t open_client(std::string hostname, unsigned short port);

    /**
     * Special: Accept a server connection, transfer to client socket.
     */
    protocolError_t special_accept_connection();

    /**
     * Special: Close client connection.
     */
    protocolError_t special_close_client_connection();

    /**
     * Return status of client connection
     * @param status pointer to destination NetworkStatus object
     */
    void status_server(NetworkStatus *status);

    /**
     * Return status of server connection
     * @param status pointer to destination NetworkStatus object
     */
    void status_client(NetworkStatus *status);

    virtual size_t available() override;
};

#endif /* NETWORKPROTOCOL_TCP */
