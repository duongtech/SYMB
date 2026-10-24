#include <stdio.h>
#include <windows.h>

// Function prototype
void target_function(int value);

int main()
{
    printf("Starting program...\n");

    // Call target_function with an arbitrary value
    int input_value = 10;
    printf("Calling target_function with value: %d\n", input_value);

    target_function(input_value);

    printf("Program execution completed.\n");
    return 0;
}

// Implementation of target_function that takes one argument
void target_function(int value)
{
    printf("Entered target_function with value: %d\n", value);

    // If statement as requested
    if (value > 5)
    {
        printf("The value %d is greater than 5.\n", value);

        // Initialize a counter for the while loop
        int counter = value;

        // While loop as requested
        while (counter > 0)
        {
            printf("Loop iteration: %d, Counter value: %d\n",
                   (value - counter + 1), counter);

            // Demonstrate some processing inside the loop
            if (counter % 2 == 0)
            {
                printf("  → %d is an even number.\n", counter);
            }
            else
            {
                printf("  → %d is an odd number.\n", counter);
            }

            counter--;
        }

        printf("While loop completed after %d iterations.\n", value);
    }
    else
    {
        printf("The value %d is less than or equal to 5.\n", value);
        printf("Skipping the while loop processing.\n");
    }

    printf("Exiting target_function.\n");
}