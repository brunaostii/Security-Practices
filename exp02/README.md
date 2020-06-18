Develop a program in C, called wordharvest, which searches a file hierarchy for files and extract words from them.

The goal is to use the contents of files to compile a list of keywords that could be used in a dictionary attack, assuming local files may contain personal information.

The files handled by the program are identified by their extension. The default extensions are .txt and .text. These can be changed by the parameter -e and passing several extensions separated by ":". For instance, the argument -e txt:text:doc:asc tells the program to search for files with the extensions .txt, .text, .doc and .asc.

Your program must consider as a word sequences of chars composed of letters and numbers. Any other char must be considered as a word separator. Your program must not consider repeated words; it must write to the output file only one instance of each identified word.

The file hierarchy used to start the search must be passed using the option -d and the output file with the option -o.

Consider, for example, the program being executed as follows: wordharvest -e txt:text:asc -d /tmp/ -o words_tmp. In this case the program must: search for files with the extensions .txt, .text and .asc; start the search from directory /tmp/; save the words found in the file words_tmp.

Your program may call external commands, such as find.

Your program is goingo to be used in the next experiment.
