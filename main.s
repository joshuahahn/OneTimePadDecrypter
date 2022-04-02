EncryptedPhrase: .word 0x5f7fb06, 0xfb06f2f8, 0xc0704fb, 0xf9fbf7f3, 0x6f306fb, 0x700f809, 0xf805f30b, 0xf300f808, 0xf7080706, 0x60700f8, 0x8f3faf3, 0x4f5f2f7, 0xf7fdf5f4, 0x801f2f7, 0x1f5f304, 0xf2f6f7f7, 0x605f7ff, 0xf2f7f9f3, 0xfaf401f7, 0x0

DecryptionSpace: .space 400 # 400 bytes of space for decrypted word to go to.

DecryptSuccess: .asciiz "Key: "
NewLine: .asciiz "\n"
Finish: .asciiz "Program complete."

.text
main:
    # Setting $a3 to be 01010101 (initial key). Difficulty is that we cannot simply addi, since the value is too large.
    addi $a3, $zero, 1 # Set $a3 to be 1
    sll $a3, $a3, 8 # Set $a3 to be 100000000
    addi $a3, $a3, 1 # Set $a3 to be 100000001
    sll $a3, $a3, 8 # Set $a3 to be 10000000100000000
    addi $a3, $a3, 1 # Set $a3 to be 10000000100000001
    sll $a3, $a3, 8 # Set $a3 to be 1000000010000000100000000
    addi $a3, $a3, 1 # Set $a3 to be 1000000010000000100000001 = 0001000000010000000100000001
    add $t7, $a3, $zero # Register $t7 will be this constant value.
    j Loop # Jump to the loop portion of the code.

Loop:
    addu $t6, $a3, $t7 # $t6 stores $a3 + $t7 = current key + 01010101 in hex.
    addi $t6, $t6, 1 # Add 1 to $t6. If the key was FFFFFFFF, then adding 1 will make it 0.
    beq $t6, $zero, End # Jump to end if we have tested all keys from 01010101 to FEFEFEFE
    la $a0, EncryptedPhrase # Load address of EncryptedPhrase into $a0
    la $a1, DecryptionSpace # Load address of DecryptionSpace into $a1
    add $a2, $zero, $a3 # Move $a3 (key value) into $a2.
    jal AddAndVerify # Call AddAndVerify
    bne $v0, $zero, Print # Call Print procedure if key is valid.
    addu $a3, $a3, $t7 # Increment key by 01010101
    j Loop # Repeat loop.

Print:
    la $a0, DecryptionSpace # Load address of DecryptionSpace into $a0
    addi $v0, $zero, 4 # Set $v0 (syscall opcode) to be 4.
    syscall # Print decrypted string
    la $a0, NewLine # Load address of NewLine into $a0
    addi $v0, $zero, 4 # Set $v0 (syscall opcode) to be 4.
    syscall # Print newline.
    addu $a3, $a3, $t7 # Increment key by 01010101.
    j Loop # Repeat loop.

End:
    la $a0, Finish # Load address of Finish into $a0.
    addi $v0, $zero, 4 # Set $v0 (syscall opcode) to be 4.
    syscall # Print finish statement.
    addi $v0, $zero, 10 # Get ready to finish progrma.
    syscall # End program.

AddAndVerify:
    # Push necessary values onto stack
    addi $sp, $sp, -16 # Move stack by -16 to store values.
    sw $ra, 12($sp) # Store return address
    sw $a2, 8($sp) # Store $a2: key
    sw $a1, 4($sp) # Store $a1: address for decrypted string
    sw $a0, 0($sp) # Store $a0: address for encrypted string

    # Reading word
    lw $t0, 0($a0) # Load word from address in $a0 into $t0.
    beq $t0, $zero, Base # Branch to Base case if $t0 is 0.
    addi $a0, $a0, 4 # Increment encrypted word's address 
    addi $a1, $a1, 4 # Increment decrypted word's address
    jal AddAndVerify # Recursive call

    # WordDecrypt & IsCandidate
    beq $v0, $zero Invalid # If the word is invalid, jump to the invalid case.
    lw $t0, 0($sp) # $t0 stores address of encrypted string
    lw $a0, 0($t0) # $a0 stores encrypted word
    lw $a1, 8($sp) # $a1 stores key
    add $a2, $zero, $v1 # $a2 stores $v1 (carry)
    jal WordDecrypt # Call WordDecrypt
    lw $t2, 4($sp) # $t2 stores address of decrypted string
    addi $sp, $sp, -4 # Make space for value of decrypted string.
    sw $v0, 0($sp) # Store value of $v0 (decrypted string) into stack.
    add $a0, $zero, $v0 # $a0 stores value of $v0 (valid?)
    jal IsCandidate # Call IsCandidate
    bne $zero, $v0, WriteWord # If $v0 is valid, write into line.
    addi $sp, $sp, 4 # Adjust stack to pop decrypted string (and ignore since it is invalid)

    # Cleanup
    lw $a0, 0($sp) # Restore original $a0 value
    lw $a1, 4($sp) # Restore original $a1 value
    lw $a2, 8($sp) # Restore original $a2 value
    lw $ra, 12($sp) # Restore original $ra value
    addi $sp, $sp, 16 # Adjust stack pointer by 4 elements
    jr $ra # Return

WriteWord:
    lw $t0, 0($sp) # Load decrypted string into $t0.
    addi $sp, $sp, 4 # Adjust stack to pop decrypted string.
    lw $t2, 4($sp) # Load address of decrypted word
    sw $t0, 0($t2) # Write decrypted word into $t2.
    addi $ra, $ra, 8 # Skip to 2 lines after WriteWord call.
    jr $ra # Return to previous AddAndVerify

Base:
    sw $zero, 0($a1) # Write 0 into address in $a1
    addi $sp, $sp, 16 # Adjust stack pointer by 4 elements
    addi $v0, $zero, 1 # Set $v0 to 1
    add $v1, $zero, $zero # Set $v1 to 0
    jr $ra # Return

Invalid:
    add $v0, $zero, $zero # Set $v0 to be 0
    lw $ra, 12($sp) # Load new return address
    addi $sp, $sp, 16 # Adjust stack pointer by 4 elements
    jr $ra # Return

WordDecrypt:
    addu $v0, $a0, $a1 # Set $v0 to $a0 + $a1
    addu $v0, $v0, $a2 # Add $a2 to $v0
    bltu $v0, $a1, Carry # If $v0 < $a1, then branch to Carry, using unsigned comparison.
    add $v1, $zero, $zero # Set $v1 to 0
    jr $ra # Jump back to main
    
Carry:
    addi $v1, $zero 1 # Set $v1 (carry) to 1.
    jr $ra # Jump back to main

IsCandidate:
    # Testing first character
    addi $t0, $zero, 255 # Set $t0 to be a mask with value 255
    and $t1, $a0, $t0 # Set $t1 to be $a0 AND $t0
    addi $t2, $zero, 64 # Set $t2 to be 64 (to be compared)
    addi $t3, $zero, 90 # Set $t3 to be 90 (to be compared)
    blt $t1, $t2, InvalidCandidate # If $t1 < 64, then branch to Invalid.
    bgt $t1, $t3, InvalidCandidate # If $t1 > 90, then branch to Invalid.

    # Testing second character
    sll $t0, $t0, 8 # Shift $t0 to the left by 8 bits. Value is now 255*2^8
    and $t1, $a0, $t0 # Set $t1 to be $a0 AND $t0
    sll $t2, $t2, 8 # Shift $t2 8 bits to the left (=64*2^8)
    sll $t3, $t3, 8 # Shift $t3 8 bits to the left (=90*2^8)
    blt $t1, $t2, InvalidCandidate # If $t1 < 64*2^8, then branch to Invalid.
    bgt $t1, $t3, InvalidCandidate # If $t1 > 90*2^8, then branch to Invalid.

    # Testing third character
    sll $t0, $t0, 8 # Shift $t0 to the left by 8 bits. Value is now 255*2^16
    and $t1, $a0, $t0 # Set $t1 to be $a0 AND $t0
    sll $t2, $t2, 8 # Shift $t2 8 bits to the left (=64*2^16)
    sll $t3, $t3, 8 # Shift $t3 8 bits to the left (=90*2^16)
    blt $t1, $t2, InvalidCandidate # If $t1 < 64*2^16, then branch to Invalid.
    bgt $t1, $t3, InvalidCandidate # If $t1 > 90*2^16, then branch to Invalid.

    # Testing fourth character
    sll $t0, $t0, 8 # Shift $t0 to the left by 8 bits. Value is now 255*2^24
    and $t1, $a0, $t0 # Set $t1 to be $a0 AND $t0
    sll $t2, $t2, 8 # Shift $t2 8 bits to the left (=64*2^24)
    sll $t3, $t3, 8 # Shift $t3 8 bits to the left (=90*2^24)
    blt $t1, $t2, InvalidCandidate # If $t1 < 64*2^24, then branch to Invalid.
    bgt $t1, $t3, InvalidCandidate # If $t1 > 90*2^24, then branch to Invalid.

    # All characters are valid
    addi $v0, $zero, 1 # Set $v0 to 1
    jr $ra # Exit to main loop

InvalidCandidate:
    add $v0, $zero, $zero # Set $v0 to 0
    jr $ra # Exit to main loop