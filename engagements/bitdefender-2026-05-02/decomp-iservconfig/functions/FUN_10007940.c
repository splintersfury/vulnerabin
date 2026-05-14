void __cdecl
FUN_10007940(undefined4 param_1,undefined4 *param_2,undefined4 param_3,int *param_4,int param_5,
            undefined4 param_6,char *param_7,uint param_8)

{
  uint *puVar1;
  char cVar2;
  undefined4 uVar3;
  int *piVar4;
  code *pcVar5;
  undefined2 uVar6;
  short sVar7;
  uint uVar8;
  lconv *plVar9;
  size_t sVar10;
  undefined4 *puVar11;
  short ****ppppsVar12;
  int iVar13;
  char ****ppppcVar14;
  char *_Control;
  uint uVar15;
  uint local_64;
  _Facet_base local_58 [4];
  int *local_54;
  uint local_50;
  int *local_4c;
  char ***local_48 [4];
  undefined4 local_38;
  uint local_34;
  short ***local_30 [4];
  uint local_20;
  uint local_1c;
  undefined2 local_18 [2];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004dfc5;
  local_10 = ExceptionList;
  uVar8 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  if ((param_8 == 0) || ((*param_7 != '+' && (*param_7 != '-')))) {
    local_50 = 0;
  }
  else {
    local_50 = 1;
  }
  if ((*(uint *)(param_5 + 0x14) & 0x3000) == 0x3000) {
    _Control = "pP";
    if (((local_50 + 2 <= param_8) && (param_7[local_50] == '0')) &&
       ((param_7[local_50 + 1] == 'x' || (param_7[local_50 + 1] == 'X')))) {
      local_50 = local_50 + 2;
    }
  }
  else {
    _Control = "eE";
  }
  uVar15 = local_50;
  local_14 = uVar8;
  local_64 = _strcspn(param_7,_Control);
  local_18[0] = 0x2e;
  plVar9 = _localeconv();
  local_18[0] = CONCAT11(local_18[0]._1_1_,*plVar9->decimal_point);
  sVar10 = _strcspn(param_7,(char *)local_18);
  local_54 = *(int **)(*(int *)(param_5 + 0x30) + 4);
  (**(code **)(*local_54 + 4))(uVar8);
  local_8 = 0;
  local_4c = (int *)FUN_10006410(local_58);
  local_8 = 0xffffffff;
  if ((local_54 != (int *)0x0) &&
     (puVar11 = (undefined4 *)(**(code **)(*local_54 + 8))(), puVar11 != (undefined4 *)0x0)) {
    (**(code **)*puVar11)(1);
  }
  FUN_10008b90(local_30,param_8,0);
  local_8 = 1;
  ppppsVar12 = local_30;
  if (7 < local_1c) {
    ppppsVar12 = (short ****)local_30[0];
  }
  (**(code **)(*local_4c + 0x2c))(param_7,param_7 + param_8,ppppsVar12);
  local_54 = *(int **)(*(int *)(param_5 + 0x30) + 4);
  (**(code **)(*local_54 + 4))();
  local_8._0_1_ = 2;
  local_4c = (int *)FUN_10008670((int)local_58);
  local_8._0_1_ = 1;
  if ((local_54 != (int *)0x0) &&
     (puVar11 = (undefined4 *)(**(code **)(*local_54 + 8))(), puVar11 != (undefined4 *)0x0)) {
    (**(code **)*puVar11)(1);
  }
  (**(code **)(*local_4c + 0x14))(local_48);
  local_8 = CONCAT31(local_8._1_3_,3);
  uVar6 = (**(code **)(*local_4c + 0x10))();
  if (sVar10 != param_8) {
    sVar7 = (**(code **)(*local_4c + 0xc))();
    ppppsVar12 = local_30;
    if (7 < local_1c) {
      ppppsVar12 = (short ****)local_30[0];
    }
    *(short *)((int)ppppsVar12 + sVar10 * 2) = sVar7;
  }
  if (sVar10 == param_8) {
    sVar10 = local_64;
  }
  ppppcVar14 = local_48;
  if (0xf < local_34) {
    ppppcVar14 = (char ****)local_48[0];
  }
  cVar2 = *(char *)ppppcVar14;
  while (((cVar2 != '\x7f' && ('\0' < cVar2)) && ((uint)(int)cVar2 < sVar10 - uVar15))) {
    sVar10 = sVar10 - (int)cVar2;
    if (local_20 < sVar10) {
      FUN_10007f70();
      goto LAB_10007d74;
    }
    if (local_1c == local_20) {
      local_64 = local_64 & 0xffffff00;
      FUN_10008930(local_30,1,local_64,sVar10,1,uVar6);
    }
    else {
      ppppsVar12 = local_30;
      if (7 < local_1c) {
        ppppsVar12 = (short ****)local_30[0];
      }
      iVar13 = local_20 - sVar10;
      puVar1 = (uint *)((int)ppppsVar12 + sVar10 * 2);
      local_20 = local_20 + 1;
      FUN_100301d0((uint *)((int)puVar1 + 2),puVar1,iVar13 * 2 + 2);
      *(undefined2 *)puVar1 = uVar6;
      uVar15 = local_50;
    }
    if ('\0' < *(char *)((int)ppppcVar14 + 1)) {
      ppppcVar14 = (char ****)((int)ppppcVar14 + 1);
    }
    cVar2 = *(char *)ppppcVar14;
  }
  uVar8 = *(uint *)(param_5 + 0x20);
  if (((*(int *)(param_5 + 0x24) < 0) || ((*(int *)(param_5 + 0x24) < 1 && (uVar8 == 0)))) ||
     (uVar8 <= local_20)) {
    iVar13 = 0;
  }
  else {
    iVar13 = uVar8 - local_20;
  }
  uVar8 = *(uint *)(param_5 + 0x14) & 0x1c0;
  local_50 = local_20;
  if (uVar8 == 0x40) {
    ppppsVar12 = local_30;
    if (7 < local_1c) {
      ppppsVar12 = (short ****)local_30[0];
    }
    puVar11 = (undefined4 *)
              FUN_10007430(param_1,(undefined4 *)local_58,param_3,param_4,(short *)ppppsVar12,uVar15
                          );
  }
  else if (uVar8 == 0x100) {
    ppppsVar12 = local_30;
    if (7 < local_1c) {
      ppppsVar12 = (short ****)local_30[0];
    }
    puVar11 = (undefined4 *)
              FUN_10007430(param_1,(undefined4 *)local_58,param_3,param_4,(short *)ppppsVar12,uVar15
                          );
    puVar11 = FUN_100073b0(param_1,(undefined4 *)local_58,*puVar11,(int *)puVar11[1],param_6,iVar13)
    ;
    iVar13 = 0;
  }
  else {
    puVar11 = FUN_100073b0(param_1,(undefined4 *)local_58,param_3,param_4,param_6,iVar13);
    iVar13 = 0;
    ppppsVar12 = local_30;
    if (7 < local_1c) {
      ppppsVar12 = (short ****)local_30[0];
    }
    puVar11 = (undefined4 *)
              FUN_10007430(param_1,(undefined4 *)local_58,*puVar11,(int *)puVar11[1],
                           (short *)ppppsVar12,uVar15);
  }
  ppppsVar12 = local_30;
  if (7 < local_1c) {
    ppppsVar12 = (short ****)local_30[0];
  }
  local_50 = local_50 - uVar15;
  puVar11 = (undefined4 *)
            FUN_10007430(param_1,(undefined4 *)local_58,*puVar11,(int *)puVar11[1],
                         (short *)((int)ppppsVar12 + uVar15 * 2),local_50);
  uVar3 = *puVar11;
  piVar4 = (int *)puVar11[1];
  *(undefined4 *)(param_5 + 0x20) = 0;
  *(undefined4 *)(param_5 + 0x24) = 0;
  FUN_100073b0(param_1,param_2,uVar3,piVar4,param_6,iVar13);
  if (0xf < local_34) {
    ppppcVar14 = (char ****)local_48[0];
    if ((0xfff < local_34 + 1) &&
       (ppppcVar14 = (char ****)local_48[0][-1],
       (char *)0x1f < (char *)((int)local_48[0] + (-4 - (int)ppppcVar14)))) goto LAB_10007d74;
    FUN_1002e346(ppppcVar14);
  }
  local_38 = 0;
  local_34 = 0xf;
  local_48[0] = (char ***)((uint)local_48[0] & 0xffffff00);
  if (7 < local_1c) {
    ppppsVar12 = (short ****)local_30[0];
    if ((0xfff < local_1c * 2 + 2) &&
       (ppppsVar12 = (short ****)local_30[0][-1],
       0x1f < (uint)((int)local_30[0] + (-4 - (int)ppppsVar12)))) {
LAB_10007d74:
      FUN_10032f7f();
      pcVar5 = (code *)swi(3);
      (*pcVar5)();
      return;
    }
    FUN_1002e346(ppppsVar12);
  }
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: _Ffmt @ 10007d80

/* Library Function - Single Match
    private: char * __cdecl std::num_put<char,class std::ostreambuf_iterator<char,struct
   std::char_traits<char> > >::_Ffmt(char *,char,int)const 
   
   Library: Visual Studio 2019 Release */

char * __thiscall
std::num_put<char,class_std::ostreambuf_iterator<char,struct_std::char_traits<char>_>_>::_Ffmt
          (num_put<char,class_std::ostreambuf_iterator<char,struct_std::char_traits<char>_>_> *this,
          char *param_1,char param_2,int param_3)

{
  char *pcVar1;
  char *pcVar2;
  uint uVar3;
  undefined3 in_stack_00000009;
  uint in_stack_00000010;
  
  *_param_2 = '%';
  pcVar1 = _param_2 + 1;
  if ((in_stack_00000010 & 0x20) != 0) {
    *pcVar1 = '+';
    pcVar1 = _param_2 + 2;
  }
  if ((in_stack_00000010 & 0x10) != 0) {
    *pcVar1 = '#';
    pcVar1 = pcVar1 + 1;
  }
  pcVar1[0] = '.';
  pcVar1[1] = '*';
  pcVar2 = pcVar1 + 2;
  if ((char)param_3 != '\0') {
    *pcVar2 = (char)param_3;
    pcVar2 = pcVar1 + 3;
  }
  uVar3 = in_stack_00000010 & 0x3000;
  if ((in_stack_00000010 & 4) == 0) {
    if (uVar3 != 0x2000) {
      if (uVar3 == 0x3000) {
        *pcVar2 = 'a';
        pcVar2[1] = '\0';
        return _param_2;
      }
      *pcVar2 = (uVar3 != 0x1000) * '\x02' + 'e';
      pcVar2[1] = '\0';
      return _param_2;
    }
  }
  else if (uVar3 != 0x2000) {
    if (uVar3 == 0x3000) {
      *pcVar2 = 'A';
      pcVar2[1] = '\0';
      return _param_2;
    }
    *pcVar2 = (uVar3 != 0x1000) * '\x02' + 'E';
    pcVar2[1] = '\0';
    return _param_2;
  }
  *pcVar2 = 'f';
  pcVar2[1] = '\0';
  return _param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_10007e40 @ 10007e40