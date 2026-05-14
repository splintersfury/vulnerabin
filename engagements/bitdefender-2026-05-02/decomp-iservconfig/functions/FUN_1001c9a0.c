void __fastcall
FUN_1001c9a0(int param_1,int param_2,uint param_3,uint param_4,uint param_5,int param_6,uint param_7
            ,uint param_8,uint param_9,uint param_10)

{
  char *pcVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  
  if ((param_8 <= param_4) && ((param_8 < param_4 || (param_7 < param_3)))) {
    while( true ) {
      uVar2 = (param_6 - param_8) - (uint)(param_5 < param_7);
      if ((uVar2 < param_10) || ((uVar2 <= param_10 && (param_5 - param_7 < param_9)))) break;
      uVar5 = param_7 + param_9;
      uVar2 = param_8 + param_10 + (uint)CARRY4(param_7,param_9);
      if ((param_4 <= uVar2) && ((param_4 < uVar2 || (param_3 <= uVar5)))) {
        uVar4 = ((param_8 - param_4) - (uint)(param_7 < param_3)) + param_10 +
                (uint)CARRY4(param_7 - param_3,param_9);
        uVar3 = (param_4 - param_8) - (uint)(param_3 < param_7);
        if (uVar3 < uVar4) {
          return;
        }
        if ((uVar3 <= uVar4) && (param_3 - param_7 <= (param_7 - param_3) + param_9)) {
          return;
        }
      }
      pcVar1 = (char *)(param_1 + -1 + param_2);
      *pcVar1 = *pcVar1 + -1;
      param_7 = uVar5;
      param_8 = uVar2;
      if (param_4 <= uVar2) {
        if (param_4 < uVar2) {
          return;
        }
        if (param_3 <= uVar5) {
          return;
        }
      }
    }
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001ca50 @ 1001ca50

/* WARNING: Removing unreachable block (ram,0x1001cbfa) */