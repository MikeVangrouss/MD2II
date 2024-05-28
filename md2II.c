/* MD2-II Hash Function */
/* by Alexander PUKALL 2005 */
/* Code free for all, even for commercial software */
/* No restriction to use. Public Domain */

/* Hash a user password in a 528-byte key (4224 bits) */
/* For BLOWFISH II */
/* compile with gcc : gcc md2II.c -o md2II */
 
/* Based on MD2 by Ronald Rivest 1989 */

/* Users never use passwords long enough and random enough. */
/* This function takes a user password as input and provides */
/* a 528-byte key as output. This 528-byte key is then passed to Blowfish II. */

/* MD2-II can be used to hash passwords for Blowfish by simply */
/* change #define n1 528 to */
/* #define n1 72 for Blowfish 576 bits or */
/* #define n1 56 for Blowfish 448 bits */

/* MD2-II can be used with other algorithms like */
/* #define n1 16 for AES-128 (128 bits) */
/* #define n1 16 for IDEA (128 bits). It avoids IDEA weak keys */
/* #define n1 21 for 3DES (168 bits). */
/* #define n1 24 for AES-192 (192 bits) */
/* #define n1 32 for AES-256 (256 bits) */

/* MD2-II can be used to create a session key from a user password */
/* and initialization vector. */

/* MD2-II is not intended for general use like MD5 or SHA1. */
/* It is only for hashing passwords. */
/* For this purpose, it is completely secure since */
/* the hash is never accessible to an attacker. */
/* So pre-image or collision attacks don't work. */


#include <stdio.h>
#include <string.h>

#define n1 528


int x1,x2,i;
unsigned char h2[n1];
unsigned char h1[n1*3];


static void init()
{
    
   x1 = 0;
   x2 = 0;
    for (i = 0; i < n1; i++)
        h2[i] = 0;
    for (i = 0; i < n1; i++)
        h1[i] = 0;
}

static void hashing(unsigned char t1[], size_t b6)
{
    static unsigned char s4[256] = 
    {   13, 199,  11,  67, 237, 193, 164,  77, 115, 184, 141, 222,  73,
        38, 147,  36, 150,  87,  21, 104,  12,  61, 156, 101, 111, 145,
       119,  22, 207,  35, 198,  37, 171, 167,  80,  30, 219,  28, 213,
       121,  86,  29, 214, 242,   6,   4,  89, 162, 110, 175,  19, 157,
         3,  88, 234,  94, 144, 118, 159, 239, 100,  17, 182, 173, 238,
        68,  16,  79, 132,  54, 163,  52,   9,  58,  57,  55, 229, 192,
       170, 226,  56, 231, 187, 158,  70, 224, 233, 245,  26,  47,  32,
        44, 247,   8, 251,  20, 197, 185, 109, 153, 204, 218,  93, 178,
       212, 137,  84, 174,  24, 120, 130, 149,  72, 180, 181, 208, 255,
       189, 152,  18, 143, 176,  60, 249,  27, 227, 128, 139, 243, 253,
        59, 123, 172, 108, 211,  96, 138,  10, 215,  42, 225,  40,  81,
        65,  90,  25,  98, 126, 154,  64, 124, 116, 122,   5,   1, 168,
        83, 190, 131, 191, 244, 240, 235, 177, 155, 228, 125,  66,  43,
       201, 248, 220, 129, 188, 230,  62,  75,  71,  78,  34,  31, 216,
       254, 136,  91, 114, 106,  46, 217, 196,  92, 151, 209, 133,  51,
       236,  33, 252, 127, 179,  69,   7, 183, 105, 146,  97,  39,  15,
       205, 112, 200, 166, 223,  45,  48, 246, 186,  41, 148, 140, 107,
        76,  85,  95, 194, 142,  50,  49, 134,  23, 135, 169, 221, 210,
       203,  63, 165,  82, 161, 202,  53,  14, 206, 232, 103, 102, 195,
       117, 250,  99,   0,  74, 160, 241,   2, 113};
       
    int b1,b2,b3,b4,b5;
   
	b4=0;
    while (b6) {
    
        for (; b6 && x2 < n1; b6--, x2++) {
            b5 = t1[b4++];
            h1[x2 + n1] = b5;
            h1[x2 + (n1*2)] = b5 ^ h1[x2];

            x1 = h2[x2] ^= s4[b5 ^ x1];
        }

        if (x2 == n1)
        {
            b2 = 0;
            x2 = 0;
            
            for (b3 = 0; b3 < (n1+2); b3++) {
                for (b1 = 0; b1 < (n1*3); b1++)
                    b2 = h1[b1] ^= s4[b2];
                b2 = (b2 + b3) % 256;
            }
           }
          }
        }

static void end(unsigned char h4[n1])
{
    
    unsigned char h3[n1];
    int i, n4;
    
    n4 = n1 - x2;
    for (i = 0; i < n4; i++) h3[i] = n4;
    hashing(h3, n4);
    hashing(h2, sizeof(h2));
    for (i = 0; i < n1; i++) h4[i] = h1[i];
}



int main()
{
	
	unsigned char h4[n1];
	int i,w;

     
/* Example hashing password 16 'A' */
/* Note : hashing(data,len of data) */
     
     unsigned char data[1]={0x41}; 
	 unsigned char text[19]; /* strcpy = null terminated string */
     
	 init();

	 for (i=0;i<16;i++)
     {
      hashing(data, 1);
     }
	 
     end(h4);

     printf("Md2-II Hash 528 bytes 'AAAAAAAAAAAAAAAA' Tab test:\n\n");
     
     w=1;
     
	 for (i=0;i<n1;i++) 
     {
      printf("%0.2X ",h4[i]);
      if (w==20) {w=0;printf("\n");}
      w++;
     }
     
/* Is the same as hashing 'AAAAAAAAAAAAAAAA' */

printf("\n\n\n");

    init();

	strcpy((char *) text,"AAAAAAAAAAAAAAAA");

	hashing(text, 16);
    end(h4);

    printf("Md2-II Hash 528 bytes 'AAAAAAAAAAAAAAAA' String test:\n\n");
    
     w=1;
     
	 for (i=0;i<n1;i++) 
     {
      printf("%0.2X ",h4[i]);
      if (w==20) {w=0;printf("\n");}
      w++;
     }
     
    printf("\n\n\n");

/* Hashing 'Hello World !' */

    init();

	strcpy((char *) text,"Hello World !");

	hashing(text, 13);
    end(h4);


    printf("Md2-II Hash 528 bytes 'Hello World !':\n\n");
    
    w=1;
     
	 for (i=0;i<n1;i++) 
     {
      printf("%0.2X ",h4[i]);
      if (w==20) {w=0;printf("\n");}
      w++;
     }
     
   printf("\n\n\n");

/* Hashing 'My secret password' */

    init();

	strcpy((char *) text,"My secret password");

	hashing(text, 18);
    end(h4);


    printf("Md2-II Hash 528 bytes 'My secret password':\n\n");
    
    w=1;
     
	 for (i=0;i<n1;i++) 
     {
      printf("%0.2X ",h4[i]);
      if (w==20) {w=0;printf("\n");}
      w++;
     }
     
    printf("\n\n\n");

	return(0);
}

/*
Md2-II Hash 528 bytes 'AAAAAAAAAAAAAAAA' Tab test:

14 DF 58 58 7D 6E 4E B3 A1 D9 BD 82 F7 BF 66 0A CA 9F E9 E8 
1F EF A5 7A 51 0B 55 55 44 34 6E FB 37 DA 7A 4C 10 0F BF 4A 
B2 AD 35 54 CF 2F 16 78 9C BC 0C 41 99 6B 15 18 96 D6 93 DF 
6E EC 58 D0 77 93 CB DE 60 FD CB C8 52 12 D3 95 B1 3B C9 EF 
9F 85 A3 BE B8 E1 45 6D 84 F8 FD FB 42 B8 A0 75 91 58 A7 AC 
B4 1E 8D 08 0C CC D9 9B 45 4E BF 67 B5 D6 86 EF F8 29 58 1B 
3C CD 66 3E 97 A7 C8 FD AD 00 54 72 AC 02 6D 34 D2 99 70 E2 
B4 C4 01 3C 28 E0 BC 2C 8C 3B 2D 0B FF A2 2B D2 CC 9F F7 89 
7C 1E EF C2 84 69 05 FE 45 58 4B C2 AE 97 15 E3 4E 45 C4 AA 
94 52 22 67 B5 7C 21 E1 AC 34 13 F1 BB 32 4A 65 8E E0 C3 90 
56 DD B1 87 5F 43 57 AE 8E 28 6F D9 39 1B 09 A2 67 82 4A 22 
B1 8B 16 97 DC 40 9C 20 8B 0D 79 6F D5 0B B4 16 28 95 BA A1 
04 C1 E9 11 53 41 58 3E F7 13 90 17 1C AF 71 D6 7F 8E B4 F0 
12 99 6E 09 30 3D BB A5 A3 52 EF F6 1E 76 7F 92 C2 A5 DE AF 
D3 A0 2B 53 16 78 6A 76 DE B0 45 B8 D5 BA 89 14 A2 65 4E E9 
BC D2 E9 6D CB BE C7 F2 12 A5 95 86 30 67 D6 4A 54 2E 17 6D 
0A A2 4F 6D AA DC 08 A2 05 67 69 73 1A D4 45 DC 03 12 25 50 
D6 3B 5D C3 32 0B 25 9D 33 48 63 16 1F D4 B6 D6 00 76 0E B1 
C4 9E E4 BD 0E 39 8A F7 F2 C7 65 6B F1 7A 3B BC 6C 0A 80 FC 
C0 68 CB C2 82 60 74 00 E7 72 48 56 9A 91 5F 8D 16 26 43 76 
B9 39 D8 0B FD D5 A4 F2 84 51 B8 BD B4 43 2E E4 72 28 56 AE 
E1 61 93 92 60 2B AF 10 EF A9 AD 9C 81 48 1F D5 30 7F 22 4F 
1D B9 F5 B4 B8 5D 75 76 5F 96 BF 7A 58 90 07 02 75 50 38 F1 
98 9C C2 31 BE 20 39 DE A4 AB BE 4C F2 2F BE B2 4A 5A 9A D7 
4C C3 8A 62 77 E7 96 C8 11 B9 85 1D 51 A5 39 13 9C D6 1E 49 
0B 0E 24 91 0B 2D 19 CE C3 B0 E8 7F DE B6 F7 25 91 E8 30 2B 
9A AE 0F C5 E5 5A 77 78 


Md2-II Hash 528 bytes 'AAAAAAAAAAAAAAAA' String test:

14 DF 58 58 7D 6E 4E B3 A1 D9 BD 82 F7 BF 66 0A CA 9F E9 E8 
1F EF A5 7A 51 0B 55 55 44 34 6E FB 37 DA 7A 4C 10 0F BF 4A 
B2 AD 35 54 CF 2F 16 78 9C BC 0C 41 99 6B 15 18 96 D6 93 DF 
6E EC 58 D0 77 93 CB DE 60 FD CB C8 52 12 D3 95 B1 3B C9 EF 
9F 85 A3 BE B8 E1 45 6D 84 F8 FD FB 42 B8 A0 75 91 58 A7 AC 
B4 1E 8D 08 0C CC D9 9B 45 4E BF 67 B5 D6 86 EF F8 29 58 1B 
3C CD 66 3E 97 A7 C8 FD AD 00 54 72 AC 02 6D 34 D2 99 70 E2 
B4 C4 01 3C 28 E0 BC 2C 8C 3B 2D 0B FF A2 2B D2 CC 9F F7 89 
7C 1E EF C2 84 69 05 FE 45 58 4B C2 AE 97 15 E3 4E 45 C4 AA 
94 52 22 67 B5 7C 21 E1 AC 34 13 F1 BB 32 4A 65 8E E0 C3 90 
56 DD B1 87 5F 43 57 AE 8E 28 6F D9 39 1B 09 A2 67 82 4A 22 
B1 8B 16 97 DC 40 9C 20 8B 0D 79 6F D5 0B B4 16 28 95 BA A1 
04 C1 E9 11 53 41 58 3E F7 13 90 17 1C AF 71 D6 7F 8E B4 F0 
12 99 6E 09 30 3D BB A5 A3 52 EF F6 1E 76 7F 92 C2 A5 DE AF 
D3 A0 2B 53 16 78 6A 76 DE B0 45 B8 D5 BA 89 14 A2 65 4E E9 
BC D2 E9 6D CB BE C7 F2 12 A5 95 86 30 67 D6 4A 54 2E 17 6D 
0A A2 4F 6D AA DC 08 A2 05 67 69 73 1A D4 45 DC 03 12 25 50 
D6 3B 5D C3 32 0B 25 9D 33 48 63 16 1F D4 B6 D6 00 76 0E B1 
C4 9E E4 BD 0E 39 8A F7 F2 C7 65 6B F1 7A 3B BC 6C 0A 80 FC 
C0 68 CB C2 82 60 74 00 E7 72 48 56 9A 91 5F 8D 16 26 43 76 
B9 39 D8 0B FD D5 A4 F2 84 51 B8 BD B4 43 2E E4 72 28 56 AE 
E1 61 93 92 60 2B AF 10 EF A9 AD 9C 81 48 1F D5 30 7F 22 4F 
1D B9 F5 B4 B8 5D 75 76 5F 96 BF 7A 58 90 07 02 75 50 38 F1 
98 9C C2 31 BE 20 39 DE A4 AB BE 4C F2 2F BE B2 4A 5A 9A D7 
4C C3 8A 62 77 E7 96 C8 11 B9 85 1D 51 A5 39 13 9C D6 1E 49 
0B 0E 24 91 0B 2D 19 CE C3 B0 E8 7F DE B6 F7 25 91 E8 30 2B 
9A AE 0F C5 E5 5A 77 78 


Md2-II Hash 528 bytes 'Hello World !':

31 A9 D0 03 3C 6B 4A 0A 4F 3D C9 71 0B 30 C5 06 02 EE CE AE 
6A FD 5A 3B 40 7B 80 E1 BA 44 2E 6A 6A 18 D3 40 02 71 8C 01 
D3 61 29 E1 F5 33 BF 30 07 6F BD 79 BC 97 A2 86 A4 49 F8 A7 
1A A7 BD 21 47 0F 1D 5C 1C 59 FA 3D 68 EC 36 63 6E A2 2D 02 
01 5F BF E1 90 DC A4 DD B5 92 8A 2A 3A FD DC 6E D3 4A 87 1F 
83 DD BB 7D 06 66 0E 29 94 A2 4F 4A D8 71 69 FD 42 FC D0 08 
0B B2 29 D5 B3 0D 71 91 03 E8 40 C1 24 57 7A 12 3D 20 05 63 
58 C0 57 23 90 83 FD 6F 6E 6C 43 54 9E 29 67 9B BC 68 50 BD 
F3 70 01 D2 18 CB B2 F4 34 BC 12 87 18 F7 26 2A 90 8E 25 28 
BA 2E AA 7E BE 35 C9 18 60 33 4B A2 A4 E3 78 68 90 2D 5F 56 
48 57 9E 72 A7 53 D9 A5 A8 A1 15 3E 39 15 B9 9A 42 B4 87 1C 
36 7D F5 21 4E 12 71 9F 61 32 27 3C 24 2B AE CE 71 81 34 87 
C6 25 67 F4 9B 77 B2 CC D4 5F 64 33 33 FE 7D 8D 2A E9 8A E3 
4E D5 D0 4C 68 D3 DF 81 0C 47 8F F2 46 B6 CB DB 09 58 DD 66 
6D 77 47 A4 CD 75 4B CC 61 F2 98 89 4B 16 86 CB 2A 9D 89 7B 
D2 7C 33 FC 37 82 51 3E 0E C8 82 01 66 F6 8F A3 0E 8C 46 FD 
07 80 0C FB 62 60 08 72 8A DC 82 DE 48 F1 44 A8 7D 40 85 EE 
FE 33 03 96 6F 28 F6 7D 12 6A 77 08 44 26 0F DD D2 68 17 E1 
08 B8 2A 50 2F A5 72 27 22 33 5D 99 AF A5 9D FD D1 7A 57 29 
11 B2 91 85 07 4D B6 8F B3 B1 0A 13 5A 33 F2 21 D3 91 BE E0 
E9 8B 8F 8F F3 EF 2E 5F A6 0A D6 FB D6 83 DC 14 92 D0 9B A6 
81 9A 06 54 8A FC 08 22 F6 50 40 03 74 E1 3D AD DC DF 49 57 
3E 2A C2 86 87 13 8C D8 9D 50 63 90 C1 AF EA D3 02 E9 B1 0E 
03 E2 C6 EF 9D 25 C0 35 DE 93 41 E9 BC C9 BD 01 2B 4C 75 8D 
BD AC C0 F5 0D C7 5B 91 E5 E4 38 46 46 5F D7 8E B0 9F 69 02 
05 37 B0 07 63 74 FD 20 7B 66 D2 99 6D B9 CC 2E 29 C2 04 77 
F2 F2 32 BE E9 D0 16 EB 


Md2-II Hash 528 bytes 'My secret password':

E0 20 C7 15 07 A2 31 E0 0B 0C 26 DF 59 6F 7F 79 D0 EE C8 3A 
61 80 C3 B1 FC 21 07 49 E1 16 48 5A A0 7E 4A 73 D5 15 87 8E 
27 F4 93 70 1C BF F2 9C 18 FA 61 84 47 A0 96 62 9F DA BC 25 
EF BD 4D 65 DB 4F 93 5A 5E 57 53 B7 33 A9 BE 2B 83 26 DD DD 
4E 06 6D BA 6E 90 3E E0 5A DA 8D 9B 83 04 14 87 2B 7E 3D 70 
70 49 8D 2D 90 AD 3C 56 4D CF 32 56 94 F5 1A 2C FF FD 79 E1 
70 69 49 E1 33 FB 81 82 2E 42 9C 97 63 BA 33 BF 82 08 AE E3 
8B 7D 78 82 C5 57 6A 8E 18 E0 29 37 D8 BC 34 82 F2 1E 4F B0 
CE AF 34 10 02 2B 18 1B D0 D5 97 D2 77 7D D4 85 E6 35 2D EB 
52 CC 33 18 26 13 DF 8F DB E2 32 77 2D 92 83 2E F4 ED 60 D8 
60 56 9F E2 EB AE 9E 71 DB 30 6E 3D 74 BA 74 8C F8 47 AD 55 
14 B1 09 78 70 62 B9 25 C7 68 51 63 BE 6A 66 78 2F 8C 39 DB 
D5 D3 93 EE 22 7C 92 A2 6C 6D 73 7A BB AE 07 7B DC 1C FD C4 
9F 95 45 95 2D AC A7 BF B9 2E 0C 1A 04 49 71 2B 29 07 EB D8 
8B 39 E5 63 2C 71 E8 5B 52 8A AA A8 03 D8 44 43 76 79 BB 6B 
2D D4 8E DC CE 58 0E 45 03 73 C9 5B 5C 15 B6 38 1E 24 92 52 
C6 1B 3A 5E 48 E7 31 0D C2 2B B7 21 B8 F7 A2 FF 20 C4 8A DD 
85 34 C0 E6 BD B0 A1 AE 98 C1 9C C0 3E 39 0A 90 25 88 E0 44 
C9 FD 25 C6 5F 42 0A 91 D6 21 CF 39 BA E2 0A 45 12 B8 7E A7 
1C 63 AB 7B B7 22 D1 29 D4 8B 6C 3F B3 BD 04 8A 9A 39 31 7B 
62 BD 4D FE 48 7D F2 0B 04 2D F8 AC D2 DD 61 85 D7 33 48 57 
E2 34 C8 EF 68 6A 8D B8 BC 3A B2 D1 81 C0 A8 A0 C4 81 97 BC 
B2 1C 2C 9F 88 F6 29 07 11 0E CD BE 3A AC 87 6E 99 0C 97 A5 
A7 0A 35 26 A9 86 5D E7 2B 48 24 72 70 CF 79 C6 06 74 44 44 
D9 D3 CB 72 F9 0B 0E 09 40 A0 CF CA 1E F8 EB 96 C4 10 BF A4 
82 A4 F9 52 C2 5A EF 8F F6 58 7E 93 12 A9 5C 03 8D BF ED 31 
48 40 76 88 3F 8A 9F 5D 

Md2-II Hash 72 bytes 'My secret password':

53 08 72 31 BF 47 2B 6F 64 95 10 6A E6 EF 47 BF 7F 4A B3 70 
32 7F 38 EE 12 26 C1 96 E4 47 13 02 06 06 C2 C6 8D 6A E6 44 
D3 97 7C 1E 6C 8E 9C 20 E6 E9 A9 12 4F BE 36 22 FE 65 20 D3 
64 92 80 95 5C 1C BC 45 08 9B 97 D7 

Md2-II Hash 56 bytes 'My secret password':

F6 23 87 44 D1 99 7E C4 92 87 BD C3 E3 5C 28 A4 E3 7A 98 D9 
77 78 96 C6 E3 96 3D 9A A2 8D AB 34 79 0C BF E1 D2 D3 88 37 
67 B2 A2 5A 68 21 B3 B6 21 77 E6 A3 90 0E E4 FD 


*/
