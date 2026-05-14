void FUN_100018e0(undefined4 param_1,int *param_2)

{
  char cVar1;
  int *piVar2;
  
  cVar1 = *(char *)((int)param_2 + 0xd);
  while (cVar1 == '\0') {
    FUN_100018e0(param_1,(int *)param_2[2]);
    piVar2 = (int *)*param_2;
    FUN_1002e346(param_2);
    param_2 = piVar2;
    cVar1 = *(char *)((int)piVar2 + 0xd);
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: Insert_node @ 10001920

/* Library Function - Multiple Matches With Same Base Name
    public: struct std::_Tree_node<unsigned int,void *> * __thiscall std::_Tree_val<struct
   std::_Tree_simple_types<unsigned int> >::_Insert_node(struct std::_Tree_id<struct
   std::_Tree_node<unsigned int,void *> *>,struct std::_Tree_node<unsigned int,void *> * const)
    public: struct std::_Tree_node<struct fuzzer::TracePC::PCTableEntry const *,void *> * __thiscall
   std::_Tree_val<struct std::_Tree_simple_types<struct fuzzer::TracePC::PCTableEntry const *>
   >::_Insert_node(struct std::_Tree_id<struct std::_Tree_node<struct fuzzer::TracePC::PCTableEntry
   const *,void *> *>,struct std::_Tree_node<struct fuzzer::TracePC::PCTableEntry const *,void *> *
   const)
    public: struct std::_Tree_node<class std::basic_string<char,struct std::char_traits<char>,class
   std::allocator<char> >,void *> * __thiscall std::_Tree_val<struct std::_Tree_simple_types<class
   std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> > >
   >::_Insert_node(struct std::_Tree_id<struct std::_Tree_node<class std::basic_string<char,struct
   std::char_traits<char>,class std::allocator<char> >,void *> *>,struct std::_Tree_node<class
   std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> >,void *> *
   const)
   
   Library: Visual Studio 2019 Release */