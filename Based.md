# Based Challenge

[Source](https://crackmes.one/crackme/64fdf93bd931496abf90994b)

This binary, when run, prompts the user for a password and checks if it is valid or not. Our objective is to try and guess the secret password without modifying the binary or finding an input that bypasses the validation.

## ltrace

In challenges like this i like to run the binary with `ltrace` to see a bit of what is going on in the background. It is a cool tool, if the password is generated dynamically and somewhere makes a `strcmp` we will be able to see it.
Sadly it is not the case.

![Screenshot ltrace-ing the program](/assets/Pasted%20image%2020231023105805.png)

## Reverse Engineering the program

I will be using `radare2` to disassemble and analyse the program.

### Main function

It is pretty clear it has been programmed in c++, we can find hints to `cin` and `cout` operators:

![Screenshot c plus plus indicators main function](/assets/Pasted%20image%2020231023110151.png)

Also the inputs expects it to be an unsigned long as we can see from the `cin` call.

Flow:
1. cout >> 'Enter password, pls:'
2. cin << input
3. aux = luna(input)
4. cmp1 (changes byte of aux to 0 if conditions are meet)
5. cmp2 'Welcome' if aux == 1 else 'Invalid password'

Looking at the flow we see some magic happens inside of the `luna` function and then there is some comparison that can overwrite the return of the `luna` function and make it so it jumps to the invalid password. Let's analyse it:

![Screenshot after luna function](/assets/Pasted%20image%2020231023111443.png)

After the `luna` function we are saving the value (one byte, probably true or false) into the local variable aux. Then we load the previously entered input into the `rax` register and we use that to compare. The two comparisons are `jbe` (jump below or equal, aka <=), the first jumps into the reassignment and the other to the second comparison. So this to code would be something like this:
```c
aux = luna(input);
if (aux <= 0x1869f || !(aux <= 0x989680)) {
	aux = 0;
}
```
Running the hex to decimal we get:
```c
aux = luna(input);
if (aux <= 99999 || !(aux <= 10000000)) {
	aux = 0;
}
```
So the first condition is for our input to be smaller than 10.000.001 and bigger than 99999.

### Luna function

Looking at the flow we can see some type of loop is going on.

![Screenshot luna function flow diagram](/assets/Pasted%20image%2020231023115221.png)

The right most leaf is where the `ret` is located and the second box is just a comparison of var != 0. Seems like a downward counter.

#### Initialization block [0x401156]

It sets the iteration variable to whatever value we passed as a parameter, and initializes another variable to 0. This second variable it is only added on during the loop and the variable from which depends we return true or false after the loop. I called it `acc`.

#### Loop body 1 [0x401172]

![Dissasembled first block fo luna function](/assets/Pasted%20image%2020231023145311.png)

In the middle of the instructions there is a save to a local variable (`auxiliar`) at `0x0040119d`. I will try to guess what it does in two different segments before and after the save to make it a bit shorter.

##### First segment
It implements a cool trick to use the `mul` operand as a division. You see the `mul` operand on 64bit words has implicit destination operand `rdx:rax` meaning the 64 least significant bits get stored into the `rax` register and the 64 most significant bits get stored into the `rdx` register. 
Before the multiplication we set `rdx` with a crazy big value that I guess is the magic number to make this work.
Then we shift right by 3 positions the 64 most significant bits of the multiplication result. This two instructions seem to be doing $\left\lfloor\dfrac{i}{10}\right\rfloor$ , I guess the magic number is crafted to overflow to the fourth bit of the most significant digits on $i \geq 10$. Cool trick.

Then $\left\lfloor\dfrac{i}{10}\right\rfloor$ is saved both in `rax` and in `rdx`. The one in `rax` is multiplied by 4 (using left shit by two bits) and then it is added the contents of `rdx` on top of it. So it is like $\left\lfloor\dfrac{i}{10}\right\rfloor\times5$.
And then multiplied by 2 (adding `rax` to itself), so we end with $\left\lfloor\dfrac{i}{10}\right\rfloor\times10$ in `rax`.
We are at `0x00401194`.

The next operation subtracts `rax` to `rcx` (the contents of $i$) saving in `rax` the value of $rax = i - (10\left\lfloor\dfrac{i}{10}\right\rfloor)$ .  Moves the value to `rdx` and saves that to the `auxiliar` local variable.
If we take a moment to look at the formula we will find out that the formula just extracts the least significant digit of an integer. Ex: If we send 20 we will get 0, if we send 35 we will get 5.

##### Second segment

Starting at `0x004011a0` the program seems to apply the same trick twice to `rax` containing the value of $i$. So we basically do  $\left\lfloor\dfrac{i}{\dfrac{10}{10}}\right\rfloor$ which is equal to  $\left\lfloor\dfrac{i}{100}\right\rfloor$ .
This operation ends in `0x004011cc` where we once more have the result inside `rax` and `rdx`. We multiply by 4 `rax` and then add `rdx` before adding `rax` to itself again making $10\left\lfloor\dfrac{i}{100}\right\rfloor$ in similar fashion as the previous segment. But then we subtract `rcx` this time `rcx` doesn't contain the value of $i$ but the intermediate step we used to calculate $\left\lfloor\dfrac{i}{100}\right\rfloor$. It contains $\left\lfloor\dfrac{i}{10}\right\rfloor$. So far the math looks like $rcx = \left\lfloor\dfrac{i}{10}\right\rfloor - 10\left\lfloor\dfrac{i}{100}\right\rfloor$.  
Then we move it to `eax` before adding it to itself and saving it into another intermediate local variable. So this second segment does $var\_10h =2(\left\lfloor\dfrac{i}{10}\right\rfloor - 10\left\lfloor\dfrac{i}{100}\right\rfloor)$.

If the first segment looked at the least significant digit of an integer this one seem to look for the second least significant digit and multiplies it by 2. Ex: if we send 112 we get
$$x =2(\left\lfloor\dfrac{112}{10}\right\rfloor - 10\left\lfloor\dfrac{112}{100}\right\rfloor)$$
$$x =2(11 - 10)$$
$$x = 2$$

#### Loop Body 2 [0x4011e6]

![Dissasembled second block of function luna](/assets/Pasted%20image%2020231023155534.png)

It starts with a small if, it checks if the last value that we saved into memory is bigger than 9, if so it subtracts 9 to it else continues with execution.

We load $2(\left\lfloor\dfrac{i}{10}\right\rfloor - 10\left\lfloor\dfrac{i}{100}\right\rfloor)$ into `edx` and $i - (10\left\lfloor\dfrac{i}{10}\right\rfloor)$ into `eax`. Add them both and add the result to the accumulator variable `sum`.

$$sum = sum + 2(\left\lfloor\dfrac{i}{10}\right\rfloor - 10\left\lfloor\dfrac{i}{100}\right\rfloor) + i - (10\left\lfloor\dfrac{i}{10}\right\rfloor)$$

From `0x004011fb` it seems the program updates the iterating local variable $i$. It seems to be doing something similar as the integer division seen before but the constant is different and the right shift is by 2 instead of 3. After some dynamic analysis of this steps I believe the operation is $i = \left\lfloor\dfrac{i}{100}\right\rfloor$. Each iteration $i$ gets integer divided by 100.

So the loop must look something like this:
```c
acc = 0;
for(i = param1; i != 0; i = i / 100) {
	part1 = i - (10 * (i/10));
	part2 = 2 * ((i/10) - 10 * (i/100));
	if (part2 > 9) {
		part2 = part2 - 9;
	}
	acc = acc + part1 + part2;
}
```

### Exiting the loop [0x401226]

![Dissasembled exit step of luna function](/assets/Pasted%20image%2020231023162427.png)

Once $i$ has reached 0 we break free from the loop. Once free it seems we apply operations to the `sum` local variable and then test, after the operations, if the `edx` register is set to zero or not. If it is not returns 0 and  if it is return 1.

Seems to be working with a conversion from unsigned to signed given the mix of operands. Example `sar` is the same as `shr` but for signed numbers also `imul` is for signed numbers too. This operations go way over my head to be able to understand it using static analysis.

If we set a break point to the `test` instruction and we feed it different inputs we can check what is really going on in here.

| input | sum (end of loop) | edx on test |
| ----- | ----------------- | ----------- |
| 1     | 1                 | 1           |
| 18    | 10                | 0           |
| 59    | 10                | 0           |
| 5958  | 19                | 9           |

Seems to focus on the last digit of the `sum` local variable. If it is zero returns true meaning it is checking if the `sum` is multiple of 10.

The whole `luna` code must look something like this:
```c
int luna(unsigned long long param1) {
	acc = 0;
	for(i = param1; i != 0; i = i / 100) {
		part1 = i - (10 * (i/10));
		part2 = 2 * ((i/10) - 10 * (i/100));
		if (part2 > 9) {
			part2 = part2 - 9;
		}
		acc = acc + part1 + part2;
	}
	if (sum % 10 == 0) {
		return 1;
	}
	return 0;
}
```

#### Function analysis

So it seem the `luna` function checks pair of digits of the given parameter. A pair each iteration. Let's call them $A$ and $B$ so $A$ will be least significant digit and $B$ the second last ($...BA$). 
Then each iteration we add $A + 2B$ if $B\leq9$  else $A + (2B-9)$. After all the loops we check the sum of the formula applied to all the pairs and see if they are multiple of 10.

We can omit the $A + (2B-9)$ if we make the restriction $B<5$ because $B$'s range is from 0 to 9 as it is a digit. Also if one pair of $AB$ is multiple of 10 we can send this pair as many times we want that the result will also be multiple of 10.
Having this in mind we can solve:
$$A,B \in \{0, 1, 2, \ldots, 9\}$$
$$(A + 2B)\mod 10 = 0$$

We can plug some numbers and quickly find some that work:

| $B$ | $A$ |
| --- | --- |
| 1   | 8   |
| 2   | 6   |
| 4   | 2   |
| 0   | 0   |
| 3   | 4   |

So 18, 26 and 42 are valid inputs for the `luna` function.

## Solving it

We have two conditions for our input:
1. $10000000 \geq input \gt 100000$
2. And the pairs of digits of input must assert that $(A + 2B)\mod 10 = 0$ is true

We just need to craft a number with pairs as we have discovered in the previous step and that falls in the desired range. 

$input = 181818$

![Screenshot solved 0](/assets/Pasted%20image%2020231023173449.png)

$input = 182634$

![Screenshot solved 1](/assets/Pasted%20image%2020231023173539.png)

$input = 420000$

![Screenshot solved 2](/assets/Pasted%20image%2020231023173652.png)
