uint __thiscall FUN_100117c0(void *this,undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  uint in_EAX;
  int local_28 [9];
  
  *(undefined1 *)((int)this + 0x34) = 1;
  if (*(char *)((int)this + 0x60) != '\0') {
    iVar1 = *(int *)(param_3 + 0xc) / 100;
    in_EAX = iVar1 / 100;
    switch(iVar1 % 100) {
    case 1:
      FUN_1000fb90(local_28,param_3);
                    /* WARNING: Subroutine does not return */
      __CxxThrowException_8(local_28,&DAT_10067584);
    case 2:
      FUN_100122b0(local_28,param_3);
                    /* WARNING: Subroutine does not return */
      __CxxThrowException_8(local_28,&DAT_1006750c);
    case 3:
      FUN_1000ef40(local_28,param_3);
                    /* WARNING: Subroutine does not return */
      __CxxThrowException_8(local_28,&DAT_10067608);
    case 4:
      FUN_1000ee70(local_28,param_3);
                    /* WARNING: Subroutine does not return */
      __CxxThrowException_8(local_28,&DAT_10067618);
    case 5:
      FUN_1000fc00(local_28,param_3);
                    /* WARNING: Subroutine does not return */
      __CxxThrowException_8(local_28,&DAT_10067548);
    }
  }
  return in_EAX & 0xffffff00;
}


// FUNCTION_END

// FUNCTION_START: FUN_100118a0 @ 100118a0