/*
Computer Security - 2020s1
EXP02

wordharvest.c: a small program for gathering words of text files
inside directories. These words are stored in a file so that they
can be used later in dictionary attacks (brute force attacks).

Students:
    Bruna Almeida Osti, RA 231024
    Rafael Cortez Sanchez, RA 094324
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#define WORD_BUFFER_SIZE 128
#define FILENAME_BUFFER_SIZE 512
#define FIND_COMMAND_RAW "find %s -name \"*.%s\" -print 2>/dev/null"

//Binary Search Tree Abstract Data Type
typedef struct bstree
{
    char content[WORD_BUFFER_SIZE];
    struct bstree *leftNode;
    struct bstree *rightNode;
} BSTree;

//Binary Search Tree operations
int tryInsert(BSTree **parent, BSTree **child, BSTree **newNode);
void addNewNode(BSTree **root, char *content);
void printTree(BSTree *root, FILE *destFile);

//Main Functions
void findAllFilesAndExtractWords(char *findCommand);
void saveWordInTree(char *word);
void extractWordsFromFile(FILE *filePointer);

//Auxiliary functions
int countColons(char *charstring);
char **getExtensions(char *types_choose, int number_of_types);

//Global variables
BSTree *wordsFound = NULL;

int tryInsert(BSTree **parent, BSTree **child, BSTree **newNode)
{
    if (*child != NULL)
    {
        *parent = *child;
        return 1;
    }
    else
    {
        *child = *newNode;
        return 0;
    }
}

void addNewNode(BSTree **root, char *content)
{
    int comparator;
    int tryInsertStatus;
    BSTree *newNode = malloc(sizeof(BSTree));
    BSTree *aux = *root;

    strcpy(newNode->content, content);
    newNode->leftNode = NULL;
    newNode->rightNode = NULL;

    if (*root == NULL)
    {
        *root = newNode;
    }
    else
    {
        while (1)
        {
            comparator = strcmp(aux->content, content);
            tryInsertStatus = 1;
            if (comparator == 0)
                return;
            else if (comparator < 0)
            {
                tryInsertStatus = tryInsert(&aux, &(aux->rightNode), &newNode);
            }
            else
            {
                tryInsertStatus = tryInsert(&aux, &(aux->leftNode), &newNode);
            }
            if (tryInsertStatus == 0)
                return;
        }
    }
}

void saveWordInTree(char *word)
{
    addNewNode(&wordsFound, word);
}

void printTree(BSTree *root, FILE *destFile)
{
    if (root == NULL)
        return;
    printTree(root->leftNode, destFile);
    fprintf(destFile, "%s\n", root->content);
    printTree(root->rightNode, destFile);
    free(root);
}

int countColons(char *charstring)
{
    char c = charstring[0];
    int counter = 0;
    int i = 1;

    for (i = 1; c != '\0'; i++)
    {
        if (c == ':')
            counter++;
        c = charstring[i];
    }
    return counter;
}

char **getExtensions(char *types_choose, int number_of_types)
{
    char **extensionList = malloc(sizeof(char *) * number_of_types);
    char *extension;
    int i = 0;
    extension = strtok(types_choose, ":");
    while (extension != NULL)
    {
        extensionList[i] = malloc(sizeof(extension));
        strcpy(extensionList[i], extension);
        i++;
        extension = strtok(NULL, ":");
    }
    return extensionList;
}

void extractWordsFromFile(FILE *filePointer)
{
    char c = getc(filePointer);
    int bufferCursor = 0;
    char wordBuffer[WORD_BUFFER_SIZE];
    while (c != EOF)
    {
        if (!isalnum(c) || (bufferCursor + 1) >= WORD_BUFFER_SIZE)
        {
            wordBuffer[bufferCursor] = '\0';
            if (strlen(wordBuffer) > 0)
                saveWordInTree(wordBuffer);
            bufferCursor = 0;
        }
        else
        {
            wordBuffer[bufferCursor] = c;
            bufferCursor++;
        }
        c = getc(filePointer);
    }
}

void findAllFilesAndExtractWords(char *findCommand)
{
    char filenameBuffer[FILENAME_BUFFER_SIZE];
    int bufferCursor = 0;
    char c;
    FILE *filePointer;
    FILE *outputPipe = popen(findCommand, "r");

    c = getc(outputPipe);
    while (c != EOF)
    {
        if (c == '\n' || (bufferCursor + 1) >= FILENAME_BUFFER_SIZE)
        {
            filenameBuffer[bufferCursor] = '\0';
            bufferCursor = 0;
            filePointer = fopen(filenameBuffer, "r");
            extractWordsFromFile(filePointer);
            fclose(filePointer);
        }
        else
        {
            filenameBuffer[bufferCursor] = c;
            bufferCursor++;
        }

        c = getc(outputPipe);
    }
    fclose(outputPipe);
}

int main(int argc, char *argv[])
{
    int opt;
    char *types_choose = NULL;
    int number_of_types;
    char *entry = NULL;
    char *output = NULL;
    char **extensions;
    int i;
    char findCommand[128];
    FILE *destFile;

    while ((opt = getopt(argc, argv, ":d:e:o:")) != -1)
    {
        switch (opt)
        {
        case 'd':
            printf("option: %c, text: %s \n", opt, optarg);
            entry = malloc(sizeof(optarg));
            strcpy(entry, optarg);
            break;
        case 'e':
            printf("option: %c, text: %s \n", opt, optarg);
            types_choose = malloc(sizeof(optarg));
            strcpy(types_choose, optarg);
            break;
        case 'o':
            printf("option: %c, text: %s \n", opt, optarg);
            output = malloc(sizeof(optarg));
            strcpy(output, optarg);
            break;
        }
    }

    if (entry == NULL || output == NULL)
    {
        if (entry == NULL && output == NULL)
        {
            printf("Opções de entrada '-d' e saída '-o' não escolhidas!\n");
            return 1;
        }

        if (entry == NULL)
        {
            printf("Opção de entrada '-d' não escolhida!\n");
            return 1;
        }
        if (output == NULL)
        {
            printf("Opção de saída '-o' não escolhida!\n");
            return 1;
        }
    }

    if (types_choose == NULL)
    {
        types_choose = malloc(sizeof("text:txt\0"));
        strcpy(types_choose, "text:txt\0");
    }

    number_of_types = countColons(types_choose) + 1;
    extensions = getExtensions(types_choose, number_of_types);

    for (i = 0; i < number_of_types; ++i)
    {
        sprintf(findCommand, FIND_COMMAND_RAW, entry, extensions[i]);
        findAllFilesAndExtractWords(findCommand);
    }
    destFile = fopen(output, "w");
    printTree(wordsFound, destFile);
    fclose(destFile);
    return 0;
}
