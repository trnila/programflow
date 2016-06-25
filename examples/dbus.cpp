#include <stdio.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>

int main(int argc, char *argv[]) {
        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message *m = NULL;
        sd_bus *bus = NULL;
        const char *path;
        int r;

        /* Connect to the system bus */
        r = sd_bus_open_system(&bus);
        if (r < 0) {
                fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
                goto finish;
        }


		char *kernel;
        /* Issue the method call and store the respons message in m */
        r = sd_bus_get_property_string(bus,
                               "org.freedesktop.hostname1",           /* service to contact */
                               "/org/freedesktop/hostname1",          /* object path */
                               "org.freedesktop.hostname1",   /* interface name */
                               "KernelRelease",                          /* method name */
                               &error,                               /* object to return error in */
                               &kernel);                                   /* return message on success */
        if (r < 0) {
                fprintf(stderr, "Failed to issue method call: %s\n", error.message);
                goto finish;
        }

		printf("Your kernel is %s.\n", kernel);


finish:
        sd_bus_error_free(&error);
        sd_bus_message_unref(m);
        sd_bus_unref(bus);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
