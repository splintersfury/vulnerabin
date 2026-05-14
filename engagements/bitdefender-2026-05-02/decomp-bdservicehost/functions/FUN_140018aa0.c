void FUN_140018aa0(undefined8 *param_1,longlong param_2)

{
  code *pcVar1;
  longlong *plVar2;
  ulonglong uVar3;
  undefined8 *****pppppuVar4;
  undefined8 *****pppppuVar5;
  ulonglong uVar6;
  char *pcVar7;
  undefined1 auStackY_f8 [32];
  undefined8 ****local_c8 [2];
  longlong local_b8;
  ulonglong uStack_b0;
  undefined8 ***local_a8;
  undefined8 ***pppuStack_a0;
  undefined8 ***local_98;
  undefined8 ***pppuStack_90;
  longlong local_88 [2];
  undefined8 local_78;
  ulonglong local_70;
  undefined8 *local_68;
  longlong local_60;
  longlong lStack_58;
  undefined8 local_50;
  ulonglong uStack_48;
  char local_2c [4];
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStackY_f8;
  pcVar7 = local_2c + 1;
  uVar6 = *(ulonglong *)(param_2 + 8);
  do {
    pcVar7 = pcVar7 + -1;
    uVar3 = uVar6 / 10;
    *pcVar7 = (char)uVar6 + (char)uVar3 * -10 + '0';
    uVar6 = uVar3;
  } while (uVar3 != 0);
  pppppuVar5 = (undefined8 *****)0x0;
  local_78 = 0;
  local_70 = 0xf;
  local_88[0] = 0;
  local_68 = param_1;
  if (pcVar7 != local_2c + 1) {
    FUN_1400106a0(local_88,(undefined8 *)pcVar7,(ulonglong)(local_2c + (1 - (longlong)pcVar7)));
  }
  pcVar7 = (char *)((longlong)&local_50 + 5);
  uVar6 = *(longlong *)(param_2 + 0x10) + 1;
  do {
    pcVar7 = pcVar7 + -1;
    uVar3 = uVar6 / 10;
    *pcVar7 = (char)uVar6 + (char)uVar3 * -10 + '0';
    uVar6 = uVar3;
  } while (uVar3 != 0);
  local_b8 = 0;
  uStack_b0 = 0xf;
  local_c8[0] = (undefined8 *****)0x0;
  if (pcVar7 != (char *)((longlong)&local_50 + 5)) {
    FUN_1400106a0((longlong *)local_c8,(undefined8 *)pcVar7,
                  (longlong)&local_50 + (5 - (longlong)pcVar7));
  }
  if (uStack_b0 - local_b8 < 9) {
    pppppuVar5 = (undefined8 *****)
                 FUN_140014ae0(local_c8,9,local_b8,pcVar7,(undefined8 *)" at line ",9);
  }
  else {
    pppppuVar4 = local_c8;
    if (0xf < uStack_b0) {
      pppppuVar4 = (undefined8 *****)local_c8[0];
    }
    if (((undefined8 *****)0x14006c410 < pppppuVar4) ||
       ((char *)((longlong)pppppuVar4 + local_b8) < " at line ")) {
      pppppuVar5 = (undefined8 *****)0x9;
    }
    else if (" at line " < pppppuVar4) {
      pppppuVar5 = pppppuVar4 + -0x2800d881;
    }
    uVar6 = local_b8 + 1;
    local_b8 = local_b8 + 9;
    FUN_1400316b0((undefined8 *)((longlong)pppppuVar4 + 9),pppppuVar4,uVar6);
    FUN_1400316b0(pppppuVar4,(undefined8 *)" at line ",(ulonglong)pppppuVar5);
    FUN_1400316b0((undefined8 *)((longlong)pppppuVar4 + (longlong)pppppuVar5),
                  (undefined8 *)((longlong)pppppuVar5 + 0x14006c411),9 - (longlong)pppppuVar5);
    pppppuVar5 = local_c8;
  }
  local_a8 = (undefined8 ***)0x0;
  local_98 = (undefined8 ***)0x0;
  pppuStack_90 = (undefined8 ***)0x0;
  local_a8 = *pppppuVar5;
  pppuStack_a0 = pppppuVar5[1];
  local_98 = pppppuVar5[2];
  pppuStack_90 = pppppuVar5[3];
  pppppuVar5[2] = (undefined8 ****)0x0;
  pppppuVar5[3] = (undefined8 ****)0xf;
  *(undefined1 *)pppppuVar5 = 0;
  pcVar7 = ", column ";
  plVar2 = FUN_140010800((longlong *)&local_a8,(undefined8 *)", column ",9);
  local_60 = *plVar2;
  lStack_58 = plVar2[1];
  local_50 = plVar2[2];
  uStack_48 = plVar2[3];
  plVar2[2] = 0;
  plVar2[3] = 0xf;
  *(undefined1 *)plVar2 = 0;
  FUN_140025910(param_1,pcVar7,&local_60,local_88);
  if (uStack_48 < 0x10) {
LAB_140018d1d:
    if (pppuStack_90 < (undefined8 ****)0x10) {
LAB_140018d58:
      local_98 = (undefined8 ****)0x0;
      pppuStack_90 = (undefined8 ****)0xf;
      local_a8 = (undefined8 ***)((ulonglong)local_a8 & 0xffffffffffffff00);
      if (0xf < uStack_b0) {
        if ((0xfff < uStack_b0 + 1) &&
           ((char *)0x1f < (char *)((longlong)local_c8[0] + (-8 - (longlong)local_c8[0][-1]))))
        goto LAB_140018e28;
        FUN_14002f180();
      }
      local_b8 = 0;
      uStack_b0 = 0xf;
      local_c8[0] = (undefined8 ****)((ulonglong)local_c8[0] & 0xffffffffffffff00);
      if (local_70 < 0x10) {
LAB_140018dea:
        FUN_14002f160(local_28 ^ (ulonglong)auStackY_f8);
        return;
      }
      if ((local_70 + 1 < 0x1000) || ((local_88[0] - *(longlong *)(local_88[0] + -8)) - 8U < 0x20))
      {
        FUN_14002f180();
        goto LAB_140018dea;
      }
      FUN_140035d28();
      goto LAB_140018e1c;
    }
    if (((longlong)pppuStack_90 + 1U < 0x1000) ||
       ((ulonglong)((longlong)local_a8 + (-8 - (longlong)local_a8[-1])) < 0x20)) {
      FUN_14002f180();
      goto LAB_140018d58;
    }
  }
  else {
    if ((uStack_48 + 1 < 0x1000) || ((local_60 - *(longlong *)(local_60 + -8)) - 8U < 0x20)) {
      FUN_14002f180();
      goto LAB_140018d1d;
    }
LAB_140018e1c:
    FUN_140035d28();
  }
  FUN_140035d28();
LAB_140018e28:
  FUN_140035d28();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140018e30 @ 140018e30