#ifndef CLI
#define CLI

#include <stdbool.h>

#ifndef CLI_MAX_LINE
/**
 * Maximum number of bytes to accept in a single line
 */
#define CLI_MAX_LINE 120
#endif

#ifndef CLI_HISTORY_LEN
/**
 * Maximum number of bytes to retain of history data
 * Define this to 0 to remove history support
 */
#define CLI_HISTORY_LEN 1000
#endif

#ifndef CLI_MAX_ARGC
/**
 * What is the maximum number of arguments we reserve space for
 */
#define CLI_MAX_ARGC 16
#endif

#ifndef CLI_MAX_PROMPT_LEN
/**
 * Maximum number of bytes in the prompt
 */
#define CLI_MAX_PROMPT_LEN 16
#endif

#ifndef CLI_SERIAL_XLATE
/**
 * Translate CR -> NL on input and output CR NL on output. This allows
 * "natural" processing when using a serial terminal.
 */
#define CLI_SERIAL_XLATE 1
#endif

/**
 * This is the structure which defines the current state of the CLI
 * NOTE: Although this structure is exposed here, it is not recommended
 * that it be interacted with directly. Use the accessor functions below to
 * interact with it. It is exposed here to make it easier to use as a static
 * structure, but all elements of the structure should be considered private
 */
struct cli {
	/**
	 * Internal buffer. This should not be accessed directly, use the
	 * access functions below
	 */
	char buffer[CLI_MAX_LINE];

#if CLI_HISTORY_LEN
	/**
	 * List of history entries
	 */
	char history[CLI_HISTORY_LEN];

	/**
	 * Are we searching through the history?
	 */
	bool searching;

	/**
	 * How far back in the history are we?
	 */
	int history_pos;
#endif

	/**
	 * Number of characters in buffer at the moment
	 */
	int len;

	/**
	 * Position of the cursor
	 */
	int cursor;

	/**
	 * Have we just parsed a full line?
	 */
	bool done;

	/**
	 * Callback function to output a single character to the user
	 * is_last will be set to true if this is the last character in this
	 * transmission - this is helpful for flushing buffers.
	 */
	void (*put_char)(void *data, char ch, bool is_last);

	/**
	 * Data to provide to the put_char callback
	 */
	void *cb_data;

	bool have_escape;
	bool have_csi;

	/**
	 * counter of the value for the CSI code
	 */
	int counter;

	char *argv[CLI_MAX_ARGC];

	char prompt[CLI_MAX_PROMPT_LEN];
};

/**
 * Start up the Embedded CLI subsystem. This should only be called once.
 */
void cli_init(struct cli *, const char *prompt,
					   void (*put_char)(void *data, char ch, bool is_last),
					   void *cb_data);

/**
 * Adds a new character into the buffer. Returns true if
 * the buffer should now be processed
 * Note: This function should not be called from an interrupt handler.
 */
bool cli_insert_char(struct cli *cli, char ch);

/**
 * Returns the nul terminated internal buffer. This will
 * return NULL if the buffer is not yet complete
 */
const char *cli_get_line(const struct cli *cli);

/**
 * Parses the internal buffer and returns it as an argc/argc combo
 * @return number of values in argv (maximum of CLI_MAX_ARGC)
 */
int cli_get_argc(struct cli *cli, char ***argv);

/**
 * Outputs the CLI prompt
 * This should be called after @ref cli_get_argc() or @ref
 * cli_get_line has been called and the command fully processed
 */
void cli_prompt(struct cli *cli);

/**
 * Retrieve a history command line
 * @param history_pos 0 is the most recent command, 1 is the one before that
 * etc...
 * @return NULL if the history buffer is exceeded
 */
const char *cli_get_history(struct cli *cli,
									 int history_pos);

#endif
