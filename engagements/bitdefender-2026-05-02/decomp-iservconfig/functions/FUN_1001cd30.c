uint * __fastcall FUN_1001cd30(uint *param_1,uint param_2,size_t param_3)

{
  uint uVar1;
  char *pcVar2;
  int iVar3;
  char cVar4;
  uint *puVar5;
  uint uVar6;
  
  iVar3 = param_2 + param_3;
  if (((int)param_2 <= iVar3) && (iVar3 < 0x10)) {
    _memset((void *)((int)param_1 + param_2),0x30,param_3);
    *(undefined2 *)(iVar3 + (int)param_1) = 0x302e;
    return (uint *)((int)param_1 + iVar3 + 2);
  }
  if (iVar3 < 1) {
    if (-4 < iVar3) {
      FUN_100301d0((uint *)((int)param_1 + (2 - iVar3)),param_1,param_2);
      *(undefined2 *)param_1 = 0x2e30;
      _memset((void *)((int)param_1 + 2),0x30,-iVar3);
      return (uint *)((int)param_1 + ((param_2 + 2) - iVar3));
    }
  }
  else if (iVar3 < 0x10) {
    puVar5 = (uint *)(iVar3 + (int)param_1);
    FUN_100301d0((uint *)((int)puVar5 + 1),puVar5,param_2 - iVar3);
    *(undefined1 *)puVar5 = 0x2e;
    return (uint *)(param_2 + 1 + (int)param_1);
  }
  puVar5 = (uint *)((int)param_1 + 1);
  if (param_2 != 1) {
    FUN_100301d0((uint *)((int)param_1 + 2),puVar5,param_2 - 1);
    *(undefined1 *)((int)param_1 + 1) = 0x2e;
    puVar5 = (uint *)(param_2 + 1 + (int)param_1);
  }
  uVar1 = iVar3 - 1;
  *(undefined1 *)puVar5 = 0x65;
  pcVar2 = (char *)((int)puVar5 + 3);
  uVar6 = 1 - (param_3 + param_2);
  if ((int)uVar1 >= 0) {
    uVar6 = uVar1;
  }
  *(char *)((int)puVar5 + 1) = ((int)uVar1 < 0) * '\x02' + '+';
  if (uVar6 < 10) {
    *(undefined1 *)((int)puVar5 + 2) = 0x30;
    *pcVar2 = (char)uVar6 + '0';
    return puVar5 + 1;
  }
  if (uVar6 < 100) {
    cVar4 = (char)(uVar6 / 10);
    *(char *)((int)puVar5 + 2) = cVar4 + '0';
    *pcVar2 = (char)uVar6 + cVar4 * -10 + '0';
    return puVar5 + 1;
  }
  *(char *)((int)puVar5 + 2) = (char)(uVar6 / 100) + '0';
  cVar4 = (char)((uVar6 % 100) / 10);
  *(char *)(puVar5 + 1) = (char)(uVar6 % 100) + cVar4 * -10 + '0';
  *pcVar2 = cVar4 + '0';
  return (uint *)((int)puVar5 + 5);
}


// FUNCTION_END

// FUNCTION_START: FUN_1001cec0 @ 1001cec0