void FUN_140002cd0(longlong param_1,uint param_2,char param_3)

{
  undefined8 *puVar1;
  uint uVar2;
  char *pcVar3;
  undefined4 local_48 [4];
  undefined8 local_38 [7];
  
  *(uint *)(param_1 + 0x10) = param_2 & 0x17;
  uVar2 = param_2 & 0x17 & *(uint *)(param_1 + 0x14);
  if (uVar2 == 0) {
    return;
  }
  if (param_3 != '\0') {
                    /* WARNING: Subroutine does not return */
    _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
  }
  if ((uVar2 & 4) == 0) {
    pcVar3 = "ios_base::failbit set";
    if ((uVar2 & 2) == 0) {
      pcVar3 = "ios_base::eofbit set";
    }
  }
  else {
    pcVar3 = "ios_base::badbit set";
  }
  puVar1 = (undefined8 *)FUN_140001c00(local_48);
  FUN_140002c10(local_38,(undefined8 *)pcVar3,puVar1);
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_38,(ThrowInfo *)&DAT_140077968);
}


// FUNCTION_END

// FUNCTION_START: FUN_140002d50 @ 140002d50