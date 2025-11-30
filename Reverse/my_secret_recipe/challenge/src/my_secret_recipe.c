#include <ctype.h>
#include <stdio.h>
#include <string.h>

typedef struct ingredient_s {
    const char *word;
    char (*func)();
} ingredient_t;

char bake() {
  return 'H';
}
char perfect() {
  return 'e';
}
char sift() {
  return 'r';
}
char flour() {
  return 'o';
}
char sugar() {
  return '{';
}
char crack() {
  return '0';
}
char eggs() {
  return 'h';
}
char melt() {
  return '_';
}
char butter() {
  return 'N';
}
char blend() {
  return '0';
}
char vanilla() {
  return '_';
}
char milk() {
  return 'y';
}
char whisk() {
  return '0';
}
char cocoa() {
  return 'u';
}
char fold() {
  return '_';
}
char baking() {
  return '6';
}
char powder() {
  return '0';
}
char swirl() {
  return 'T';
}
char cream() {
  return '_';
}
char chop() {
  return 'M';
}
char cherry() {
  return 'y';
}
char toss() {
  return '_';
}
char sprinkles() {
  return 'S';
}
char preheat() {
  return '3';
}
char oven() {
  return 'c';
}
char grease() {
  return 'R';
}
char pan() {
  return 'e';
}
char line() {
  return 'T';
}
char parchment() {
  return '_';
}
char timer() {
  return 'C';
}
char light() {
  return '4';
}
char candle() {
  return 'k';
}
char plate() {
  return '3';
}
char garnish() {
  return '_';
}
char frosting() {
  return 'R';
}
char pinch() {
  return '3';
}
char salt() {
  return 'c';
}
char crushed() {
  return '1';
}
char nuts() {
  return 'p';
}
char touch() {
  return 'e';
}
char sweetness() {
  return '}';
}

ingredient_t ingredients[] = {
{"bake", bake}, 
{"perfect", perfect}, 
{"sift", sift}, 
{"flour", flour}, 
{"sugar", sugar},
{"crack", crack}, 
{"eggs", eggs}, 
{"melt", melt}, 
{"butter", butter}, 
{"blend", blend}, 
{"vanilla", vanilla}, 
{"milk", milk}, 
{"whisk", whisk}, 
{"cocoa", cocoa}, 
{"fold", fold}, 
{"baking", baking}, 
{"powder", powder}, 
{"swirl", swirl}, 
{"cream", cream}, 
{"chop", chop}, 
{"cherry", cherry}, 
{"toss", toss}, 
{"sprinkles", sprinkles}, 
{"preheat", preheat}, 
{"oven", oven}, 
{"grease", grease}, 
{"pan", pan}, 
{"line", line}, 
{"parchment", parchment}, 
{"timer", timer}, 
{"light", light}, 
{"candle", candle}, 
{"plate", plate}, 
{"garnish", garnish}, 
{"frosting", frosting}, 
{"pinch", pinch}, 
{"salt", salt}, 
{"crushed", crushed}, 
{"nuts", nuts}, 
{"touch", touch},
{"sweetness", sweetness}
};

#define NUM_INGREDIENTS (sizeof(ingredients) / sizeof(ingredients[0]))

void normalize_word(char *word) {
    // Remove punctuation, convert to lowercase
    int i = 0, j = 0;
    while (word[i]) {
        if (isalpha(word[i])) {
            word[j++] = tolower(word[i]);
        }
        i++;
    }
    word[j] = '\0';
}

void parse_recipe(const char *text, char *flag) {
    char buffer[1024];
    strncpy(buffer, text, sizeof(buffer));
    buffer[sizeof(buffer)-1] = '\0';

    char *word = strtok(buffer, " \n");
    while (word != NULL) {
        normalize_word(word);

        for (size_t i = 0; i < NUM_INGREDIENTS; i++) {
          // printf("%s\n", word);
            if (strcmp(word, ingredients[i].word) == 0) {
                flag[i] = ingredients[i].func();  // Call matched function
                break;
            }
        }

        word = strtok(NULL, " \n");
    }
}

// Hero{0h_N0_y0u_60T_My_S3cReT_C4k3_R3c1pe}
int main(int argc, char **argv) {
  if(argc < 2) {
    printf("[-] Missing arguments, usage %s <FLAG_STR>\n", argv[0]);
    return 1;
  }
  char flag[41] = {0};
  char *secret_recipe = "\tTo bake the perfect flag-cake: sift the flour, add sugar, crack some eggs,\n \
\tmelt the butter, blend in vanilla and milk, whisk the cocoa, fold in the baking powder,\n \
\tswirl in the cream, chop some cherry, toss on sprinkles, preheat the oven, grease the pan,\n \
\tline it with parchment, set the timer, light a candle, serve on a plate, and garnish with frosting,\n \
\ta pinch of salt, and crushed nuts for that final touch of sweetness. \n\n";
  printf("🍰 The Chef’s Secret Recipe: \n %s", secret_recipe);
  parse_recipe(secret_recipe, flag);
  if(!strcmp(flag, argv[1])) {
    printf("[+] Good job you here is your flag: %s\n", flag);
  } else {
    printf("[-] Nope\n");
  }
  
  return 0;
}
