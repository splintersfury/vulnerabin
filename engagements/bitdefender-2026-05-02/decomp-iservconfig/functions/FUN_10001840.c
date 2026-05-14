void FUN_10001840(void)

{
  code *pcVar1;
  
  FUN_1002c854("map/set too long");
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: ~_Tree<> @ 10001850

/* Library Function - Multiple Matches With Same Base Name
    public: __thiscall std::_Tree<class std::_Tset_traits<unsigned int,struct std::less<unsigned
   int>,class fuzzer::fuzzer_allocator<unsigned int>,0> >::~_Tree<class std::_Tset_traits<unsigned
   int,struct std::less<unsigned int>,class fuzzer::fuzzer_allocator<unsigned int>,0> >(void)
    public: __thiscall std::_Tree<class std::_Tset_traits<struct fuzzer::TracePC::PCTableEntry const
   *,struct std::less<struct fuzzer::TracePC::PCTableEntry const *>,class
   fuzzer::fuzzer_allocator<struct fuzzer::TracePC::PCTableEntry const *>,0> >::~_Tree<class
   std::_Tset_traits<struct fuzzer::TracePC::PCTableEntry const *,struct std::less<struct
   fuzzer::TracePC::PCTableEntry const *>,class fuzzer::fuzzer_allocator<struct
   fuzzer::TracePC::PCTableEntry const *>,0> >(void)
   
   Library: Visual Studio 2019 Release */

void __fastcall ~_Tree<>(int *param_1)

{
  int *piVar1;
  void *pvVar2;
  int *piVar3;
  
  pvVar2 = (void *)*param_1;
  piVar3 = *(int **)((int)pvVar2 + 4);
  if (*(char *)((int)*(int **)((int)pvVar2 + 4) + 0xd) == '\0') {
    do {
      FUN_100018e0(param_1,(int *)piVar3[2]);
      piVar1 = (int *)*piVar3;
      FUN_1002e346(piVar3);
      piVar3 = piVar1;
    } while (*(char *)((int)piVar1 + 0xd) == '\0');
    pvVar2 = (void *)*param_1;
  }
  FUN_1002e346(pvVar2);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10001890 @ 10001890