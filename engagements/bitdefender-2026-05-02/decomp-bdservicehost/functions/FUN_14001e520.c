undefined8 *
FUN_14001e520(undefined8 *param_1,undefined8 param_2,longlong *param_3,undefined8 param_4)

{
  longlong lVar1;
  ulonglong uVar2;
  longlong *plVar3;
  undefined8 uVar4;
  undefined1 uVar5;
  undefined1 uVar6;
  undefined7 uVar7;
  char local_78 [16];
  undefined8 *local_68;
  ulonglong uStack_60;
  undefined8 *local_58;
  longlong *local_48;
  longlong local_40 [3];
  
  uVar5 = (undefined1)param_4;
  uVar7 = (undefined7)((ulonglong)param_4 >> 8);
  *param_1 = param_2;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  *(undefined1 *)(param_1 + 0xd) = 0;
  local_68 = param_1 + 0xe;
  param_1[0x15] = 0;
  uVar6 = uVar5;
  local_58 = param_1;
  local_48 = param_3;
  if (param_3[7] != 0) {
    uVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)(param_3[7],local_68);
    param_1[0x15] = uVar4;
  }
  *(undefined1 *)(param_1 + 0x16) = uVar5;
  FUN_14001de50((char *)(param_1 + 0x17),'\b');
  local_78[0] = '\x01';
  uVar2 = param_1[7];
  if (((longlong)uVar2 < 0) && (uVar2 != 0)) {
    lVar1 = -((~uVar2 >> 5) * 4 + 4);
  }
  else {
    lVar1 = (uVar2 >> 5) * 4;
  }
  local_68 = (undefined8 *)(param_1[4] + lVar1);
  uStack_60 = (ulonglong)((uint)uVar2 & 0x1f);
  FUN_1400214b0(param_1 + 4,local_40,&local_68,CONCAT71(uVar7,uVar6),local_78);
  plVar3 = (longlong *)param_3[7];
  if (plVar3 != (longlong *)0x0) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(plVar3,plVar3 != param_3);
    param_3[7] = 0;
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001e680 @ 14001e680