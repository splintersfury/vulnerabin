void __thiscall
FUN_10006920(char *param_1,undefined4 *param_2,undefined4 param_3,int *param_4,int param_5,
            undefined4 param_6,double param_7)

{
  int iVar1;
  code *pcVar2;
  char *pcVar3;
  uint uVar4;
  num_put<char,class_std::ostreambuf_iterator<char,struct_std::char_traits<char>_>_> *this;
  char ****ppppcVar5;
  uint uVar6;
  uint local_38;
  char ***local_34 [4];
  uint local_24;
  uint local_20;
  undefined1 local_1c [8];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004de9d;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_24 = 0;
  local_20 = 0xf;
  local_34[0] = (char ***)0x0;
  local_8 = 0;
  uVar4 = *(uint *)(param_5 + 0x14) & 0x3000;
  if (uVar4 == 0x3000) {
    local_38 = 0xffffffff;
    uVar6 = 0xd;
  }
  else {
    iVar1 = *(int *)(param_5 + 0x1c);
    uVar6 = *(uint *)(param_5 + 0x18);
    if ((iVar1 < 0) || ((iVar1 < 1 && (uVar6 == 0)))) {
      if (uVar6 == 0 && iVar1 == 0) {
        if (uVar4 == 0) {
          uVar6 = 1;
          goto LAB_10006a1c;
        }
        uVar6 = 0;
      }
      else {
        uVar6 = 6;
      }
    }
    if ((uVar4 == 0x2000) &&
       (_DAT_100616a8 <
        (double)CONCAT44((uint)((ulonglong)param_7 >> 0x20) & _UNK_10061704,
                         SUB84(param_7,0) & _DAT_10061700))) {
      FUN_10032fd0(param_7,(int *)&local_38);
      uVar6 = uVar6 + (int)(((local_38 ^ (int)local_38 >> 0x1f) - ((int)local_38 >> 0x1f)) * 0x7597)
                      / 100000;
    }
  }
LAB_10006a1c:
  FUN_10005410(local_34,-(uint)(0xffffffcd < uVar6) | uVar6 + 0x32,'\0');
  pcVar3 = std::num_put<char,class_std::ostreambuf_iterator<char,struct_std::char_traits<char>_>_>::
           _Ffmt(this,param_1,(char)local_1c,0x4c);
  ppppcVar5 = local_34;
  if (0xf < local_20) {
    ppppcVar5 = (char ****)local_34[0];
  }
  uVar4 = FUN_10008b60((char *)ppppcVar5,local_24,pcVar3);
  ppppcVar5 = local_34;
  if (0xf < local_20) {
    ppppcVar5 = (char ****)local_34[0];
  }
  FUN_10007940(param_1,param_2,param_3,param_4,param_5,param_6,(char *)ppppcVar5,uVar4);
  if (0xf < local_20) {
    ppppcVar5 = (char ****)local_34[0];
    if ((0xfff < local_20 + 1) &&
       (ppppcVar5 = (char ****)local_34[0][-1],
       (char *)0x1f < (char *)((int)local_34[0] + (-4 - (int)ppppcVar5)))) {
      FUN_10032f7f();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_1002e346(ppppcVar5);
  }
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10006af0 @ 10006af0

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */