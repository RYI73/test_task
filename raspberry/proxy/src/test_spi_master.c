// master.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>

#define SPI_DEV "/dev/spidev0.0"
#define SPI_SPEED 1000000
#define PKT_LEN 32

static int spi_init(void)
{
    int fd = open(SPI_DEV, O_RDWR);
    if (fd < 0) {
        perror("open spidev");
        return -1;
    }

    uint8_t mode = 0;
    uint8_t bits = 8;
    uint32_t speed = SPI_SPEED;

    ioctl(fd, SPI_IOC_WR_MODE, &mode);
    ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);

    return fd;
}

static void spi_write_packet(int fd, uint8_t base)
{
    uint8_t tx[PKT_LEN];
    uint8_t rx[PKT_LEN] = {0};

    for (int i = 0; i < PKT_LEN; i++)
        tx[i] = base + i;

    struct spi_ioc_transfer t = {
        .tx_buf = (unsigned long)tx,
        .rx_buf = (unsigned long)rx,
        .len = PKT_LEN,
        .speed_hz = SPI_SPEED,
        .bits_per_word = 8,
    };

    ioctl(fd, SPI_IOC_MESSAGE(1), &t);

    printf("MASTER sent: ");
    for (int i = 0; i < PKT_LEN; i++)
        printf("%02x ", tx[i]);
    printf("\n");
}

static void spi_read_packet(int fd)
{
    uint8_t tx[PKT_LEN] = {0};
    uint8_t rx[PKT_LEN];

    struct spi_ioc_transfer t = {
        .tx_buf = (unsigned long)tx,
        .rx_buf = (unsigned long)rx,
        .len = PKT_LEN,
        .speed_hz = SPI_SPEED,
        .bits_per_word = 8,
    };

    ioctl(fd, SPI_IOC_MESSAGE(1), &t);

    printf("MASTER received: ");
    for (int i = 0; i < PKT_LEN; i++)
        printf("%02x ", rx[i]);
    printf("\n");
}

int main(void)
{
    int fd = spi_init();
    if (fd < 0) return 1;

    sleep(2); // дати слейву підготуватися

    printf("=== TEST 1: master -> slave ===\n");
    for (int i = 0; i < 3; i++) {
        spi_write_packet(fd, i * 0x70);
        usleep(200000);
    }

    printf("=== TEST 2: master <- slave ===\n");
    for (int i = 0; i < 3; i++) {
        spi_read_packet(fd);
        usleep(200000);
    }

    close(fd);
    return 0;
}
