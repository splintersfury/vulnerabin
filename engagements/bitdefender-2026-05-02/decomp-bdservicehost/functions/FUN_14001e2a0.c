ulonglong FUN_14001e2a0(longlong param_1,undefined8 param_2,undefined8 param_3,longlong param_4)

{
  ulonglong in_RAX;
  int iVar1;
  undefined8 local_48 [9];
  
  *(undefined1 *)(param_1 + 0x28) = 1;
  if (*(char *)(param_1 + 0x29) != '\0') {
    iVar1 = *(int *)(param_4 + 0x18) / 100;
    in_RAX = (ulonglong)(uint)((iVar1 / 100) * 100);
    iVar1 = iVar1 % 100;
    if (iVar1 == 1) {
      FUN_14001e0d0(local_48,param_4);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_48,(ThrowInfo *)&DAT_140077c10);
    }
    if (iVar1 == 2) {
      FUN_14001d320(local_48,param_4);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_48,(ThrowInfo *)&DAT_140077d70);
    }
    if (iVar1 == 3) {
      FUN_14001d4c0(local_48,param_4);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_48,(ThrowInfo *)&DAT_140077cc0);
    }
    if (iVar1 == 4) {
      FUN_14001d490(local_48,param_4);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_48,(ThrowInfo *)&DAT_140077ce0);
    }
    if (iVar1 == 5) {
      FUN_14001f3f0(local_48,param_4);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_48,(ThrowInfo *)&DAT_140077ba8);
    }
  }
  return in_RAX & 0xffffffffffffff00;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001e3b0 @ 14001e3b0