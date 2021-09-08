/*
Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/* headers */

#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include "structmember.h"

#if PY_VERSION_HEX >= 0x02060000
#include "bytesobject.h"
#elif PY_VERSION_HEX < 0x02060000
#define PyBytes_AsString PyString_AsString
#define PyBytes_Check PyString_Check
#define PyBytes_FromStringAndSize PyString_FromStringAndSize
#endif

#include <time.h>
#include <yara.h>

#if PY_VERSION_HEX < 0x02050000 && !defined(PY_SSIZE_T_MIN)
typedef int Py_ssize_t;
#define PY_SSIZE_T_MAX INT_MAX
#define PY_SSIZE_T_MIN INT_MIN
#endif

#ifndef PyVarObject_HEAD_INIT
#define PyVarObject_HEAD_INIT(type, size) PyObject_HEAD_INIT(type) size,
#endif

#if PY_VERSION_HEX < 0x03020000
typedef long Py_hash_t;
#endif

#if PY_MAJOR_VERSION >= 3
#define PY_STRING(x) PyUnicode_DecodeUTF8(x, strlen(x), "ignore" )
#define PY_STRING_FORMAT(...) PyUnicode_FromFormat(__VA_ARGS__)
#define PY_STRING_TO_C(x) PyUnicode_AsUTF8(x)
#define PY_STRING_CHECK(x) PyUnicode_Check(x)
#else
#define PY_STRING(x) PyString_FromString(x)
#define PY_STRING_FORMAT(...) PyString_FromFormat(__VA_ARGS__)
#define PY_STRING_TO_C(x) PyString_AsString(x)
#define PY_STRING_CHECK(x) (PyString_Check(x) || PyUnicode_Check(x))
#endif

#if PY_VERSION_HEX < 0x03020000
#define PyDescr_NAME(x) (((PyDescrObject*)x)->d_name)
#endif

/* Module globals */

static PyObject* YaraError = NULL;
static PyObject* YaraSyntaxError = NULL;
static PyObject* YaraTimeoutError = NULL;
static PyObject* YaraWarningError = NULL;


#define YARA_DOC "\
This module allows you to apply YARA rules to files or strings.\n\
\n\
For complete documentation please visit:\n\
https://plusvic.github.io/yara\n"

#if defined(_WIN32) || defined(__CYGWIN__)
#include <string.h>
#define strdup _strdup
#endif

// Match object

typedef struct
{
  PyObject_HEAD
  PyObject* rule;
  PyObject* ns;
  PyObject* tags;
  PyObject* meta;
  PyObject* strings;

} Match;

static PyMemberDef Match_members[] = {
  {
    "rule",
    T_OBJECT_EX,
    offsetof(Match, rule),
    READONLY,
    "Name of the matching rule"
  },
  {
    "namespace",
    T_OBJECT_EX,
    offsetof(Match, ns),
    READONLY,
    "Namespace of the matching rule"
  },
  {
    "tags",
    T_OBJECT_EX,
    offsetof(Match, tags),
    READONLY,
    "List of tags associated to the rule"
  },
  {
    "meta",
    T_OBJECT_EX,
    offsetof(Match, meta),
    READONLY,
    "Dictionary with metadata associated to the rule"
  },
  {
    "strings",
    T_OBJECT_EX,
    offsetof(Match, strings),
    READONLY,
    "Tuple with offsets and strings that matched the file"
  },
  { NULL } // End marker
};

static PyObject* Match_NEW(
    const char* rule,
    const char* ns,
    PyObject* tags,
    PyObject* meta,
    PyObject* strings);

static void Match_dealloc(
  PyObject* self);

static PyObject* Match_repr(
    PyObject* self);

static PyObject* Match_getattro(
    PyObject* self,
    PyObject* name);

static PyObject* Match_richcompare(
    PyObject* self,
    PyObject* other,
    int op);

static Py_hash_t Match_hash(
    PyObject* self);


static PyMethodDef Match_methods[] =
{
  { NULL },
};

static PyTypeObject Match_Type = {
  PyVarObject_HEAD_INIT(NULL, 0)
  "yara.Match",               /*tp_name*/
  sizeof(Match),              /*tp_basicsize*/
  0,                          /*tp_itemsize*/
  (destructor)Match_dealloc,  /*tp_dealloc*/
  0,                          /*tp_print*/
  0,                          /*tp_getattr*/
  0,                          /*tp_setattr*/
  0,                          /*tp_compare*/
  Match_repr,                 /*tp_repr*/
  0,                          /*tp_as_number*/
  0,                          /*tp_as_sequence*/
  0,                          /*tp_as_mapping*/
  Match_hash,                 /*tp_hash */
  0,                          /*tp_call*/
  0,                          /*tp_str*/
  Match_getattro,             /*tp_getattro*/
  0,                          /*tp_setattro*/
  0,                          /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
  "Match class",              /* tp_doc */
  0,                          /* tp_traverse */
  0,                          /* tp_clear */
  Match_richcompare,          /* tp_richcompare */
  0,                          /* tp_weaklistoffset */
  0,                          /* tp_iter */
  0,                          /* tp_iternext */
  Match_methods,              /* tp_methods */
  Match_members,              /* tp_members */
  0,                          /* tp_getset */
  0,                          /* tp_base */
  0,                          /* tp_dict */
  0,                          /* tp_descr_get */
  0,                          /* tp_descr_set */
  0,                          /* tp_dictoffset */
  0,                          /* tp_init */
  0,                          /* tp_alloc */
  0,                          /* tp_new */
};

// Rule object

typedef struct
{
  PyObject_HEAD
  PyObject* identifier;
  PyObject* tags;
  PyObject* meta;
  PyObject* global;
  PyObject* private;
} Rule;

static void Rule_dealloc(
    PyObject* self);

static PyObject* Rule_getattro(
    PyObject* self,
    PyObject* name);

static PyMemberDef Rule_members[] = {
  {
    "is_global",
    T_OBJECT_EX,
    offsetof(Rule, global),
    READONLY,
    "Rule is global"
  },
  {
    "is_private",
    T_OBJECT_EX,
    offsetof(Rule, private),
    READONLY,
    "Rule is private"
  },
  {
    "identifier",
    T_OBJECT_EX,
    offsetof(Rule, identifier),
    READONLY,
    "Name of the rule"
  },
  {
    "tags",
    T_OBJECT_EX,
    offsetof(Rule, tags),
    READONLY,
    "Tags for the rule"
  },
  {
    "meta",
    T_OBJECT_EX,
    offsetof(Rule, meta),
    READONLY,
    "Meta for the rule"
  },
  { NULL } // End marker
};

static PyMethodDef Rule_methods[] =
{
  { NULL, NULL }
};

static PyTypeObject Rule_Type = {
  PyVarObject_HEAD_INIT(NULL, 0)
  "yara.Rule",                /*tp_name*/
  sizeof(Rule),               /*tp_basicsize*/
  0,                          /*tp_itemsize*/
  (destructor) Rule_dealloc,  /*tp_dealloc*/
  0,                          /*tp_print*/
  0,                          /*tp_getattr*/
  0,                          /*tp_setattr*/
  0,                          /*tp_compare*/
  0,                          /*tp_repr*/
  0,                          /*tp_as_number*/
  0,                          /*tp_as_sequence*/
  0,                          /*tp_as_mapping*/
  0,                          /*tp_hash */
  0,                          /*tp_call*/
  0,                          /*tp_str*/
  Rule_getattro,              /*tp_getattro*/
  0,                          /*tp_setattro*/
  0,                          /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
  "Rule class",               /* tp_doc */
  0,                          /* tp_traverse */
  0,                          /* tp_clear */
  0,                          /* tp_richcompare */
  0,                          /* tp_weaklistoffset */
  0,                          /* tp_iter */
  0,                          /* tp_iternext */
  Rule_methods,               /* tp_methods */
  Rule_members,               /* tp_members */
  0,                          /* tp_getset */
  0,                          /* tp_base */
  0,                          /* tp_dict */
  0,                          /* tp_descr_get */
  0,                          /* tp_descr_set */
  0,                          /* tp_dictoffset */
  0,                          /* tp_init */
  0,                          /* tp_alloc */
  0,                          /* tp_new */
};


// Rules object

typedef struct
{
  PyObject_HEAD
  PyObject* externals;
  YR_RULES* rules;
  YR_RULE* iter_current_rule;
} Rules;


static Rules* Rules_NEW(void);

static void Rules_dealloc(
    PyObject* self);

static PyObject* Rules_match(
    PyObject* self,
    PyObject* args,
    PyObject* keywords);

static PyObject* Rules_save(
    PyObject* self,
    PyObject* args,
    PyObject* keywords);

static PyObject* Rules_profiling_info(
    PyObject* self,
    PyObject* args);

static PyObject* Rules_getattro(
    PyObject* self,
    PyObject* name);

static PyObject* Rules_next(
    PyObject* self);

static PyMethodDef Rules_methods[] =
{
  {
    "match",
    (PyCFunction) Rules_match,
    METH_VARARGS | METH_KEYWORDS
  },
  {
    "save",
    (PyCFunction) Rules_save,
    METH_VARARGS | METH_KEYWORDS
  },
  {
    "profiling_info",
    (PyCFunction) Rules_profiling_info,
    METH_NOARGS
  },
  {
    NULL,
    NULL
  }
};

static PyTypeObject Rules_Type = {
  PyVarObject_HEAD_INIT(NULL, 0)
  "yara.Rules",               /*tp_name*/
  sizeof(Rules),              /*tp_basicsize*/
  0,                          /*tp_itemsize*/
  (destructor) Rules_dealloc, /*tp_dealloc*/
  0,                          /*tp_print*/
  0,                          /*tp_getattr*/
  0,                          /*tp_setattr*/
  0,                          /*tp_compare*/
  0,                          /*tp_repr*/
  0,                          /*tp_as_number*/
  0,                          /*tp_as_sequence*/
  0,                          /*tp_as_mapping*/
  0,                          /*tp_hash */
  0,                          /*tp_call*/
  0,                          /*tp_str*/
  Rules_getattro,             /*tp_getattro*/
  0,                          /*tp_setattro*/
  0,                          /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
  "Rules class",              /* tp_doc */
  0,                          /* tp_traverse */
  0,                          /* tp_clear */
  0,                          /* tp_richcompare */
  0,                          /* tp_weaklistoffset */
  PyObject_SelfIter,          /* tp_iter */
  (iternextfunc) Rules_next,  /* tp_iternext */
  Rules_methods,              /* tp_methods */
  0,                          /* tp_members */
  0,                          /* tp_getset */
  0,                          /* tp_base */
  0,                          /* tp_dict */
  0,                          /* tp_descr_get */
  0,                          /* tp_descr_set */
  0,                          /* tp_dictoffset */
  0,                          /* tp_init */
  0,                          /* tp_alloc */
  0,                          /* tp_new */
};

typedef struct _CALLBACK_DATA
{
  PyObject* matches;
  PyObject* callback;
  PyObject* modules_data;
  PyObject* modules_callback;
  PyObject* warnings_callback;
  int which;

} CALLBACK_DATA;


// Forward declarations for handling module data.
PyObject* convert_structure_to_python(
    YR_OBJECT_STRUCTURE* structure);


PyObject* convert_array_to_python(
    YR_OBJECT_ARRAY* array);


PyObject* convert_dictionary_to_python(
    YR_OBJECT_DICTIONARY* dictionary);


PyObject* convert_object_to_python(
    YR_OBJECT* object)
{
  PyObject* result = NULL;

  if (object == NULL)
    return NULL;

  switch(object->type)
  {
    case OBJECT_TYPE_INTEGER:
      if (object->value.i != YR_UNDEFINED)
        result = Py_BuildValue("l", object->value.i);
      break;

    case OBJECT_TYPE_STRING:
      if (object->value.ss != NULL)
        result = PyBytes_FromStringAndSize(
            object->value.ss->c_string,
            object->value.ss->length);
      break;

    case OBJECT_TYPE_STRUCTURE:
      result = convert_structure_to_python(object_as_structure(object));
      break;

    case OBJECT_TYPE_ARRAY:
      result = convert_array_to_python(object_as_array(object));
      break;

    case OBJECT_TYPE_FUNCTION:
      // Do nothing with functions...
      break;

    case OBJECT_TYPE_DICTIONARY:
      result = convert_dictionary_to_python(object_as_dictionary(object));
      break;

    case OBJECT_TYPE_FLOAT:
      if (!isnan(object->value.d))
        result = Py_BuildValue("d", object->value.d);
      break;

    default:
      break;
  }

  return result;
}


PyObject* convert_structure_to_python(
    YR_OBJECT_STRUCTURE* structure)
{
  YR_STRUCTURE_MEMBER* member;

  PyObject* py_object;
  PyObject* py_dict = PyDict_New();

  if (py_dict == NULL)
    return py_dict;

  member = structure->members;

  while (member != NULL)
  {
    py_object = convert_object_to_python(member->object);

    if (py_object != NULL)
    {
      PyDict_SetItemString(py_dict, member->object->identifier, py_object);
      Py_DECREF(py_object);
    }

    member =member->next;
  }

  return py_dict;
}


PyObject* convert_array_to_python(
    YR_OBJECT_ARRAY* array)
{
  PyObject* py_object;
  PyObject* py_list = PyList_New(0);

  if (py_list == NULL)
    return py_list;

  // If there is nothing in the list, return an empty Python list
  if (array->items == NULL)
    return py_list;

  for (int i = 0; i < array->items->length; i++)
  {
    py_object = convert_object_to_python(array->items->objects[i]);

    if (py_object != NULL)
    {
      PyList_Append(py_list, py_object);
      Py_DECREF(py_object);
    }
  }

  return py_list;
}


PyObject* convert_dictionary_to_python(
    YR_OBJECT_DICTIONARY* dictionary)
{
  PyObject* py_object;
  PyObject* py_dict = PyDict_New();

  if (py_dict == NULL)
    return py_dict;

  // If there is nothing in the YARA dictionary, return an empty Python dict
  if (dictionary->items == NULL)
    return py_dict;

  for (int i = 0; i < dictionary->items->used; i++)
  {
    py_object = convert_object_to_python(dictionary->items->objects[i].obj);

    if (py_object != NULL)
    {
      PyDict_SetItemString(
          py_dict,
          dictionary->items->objects[i].key->c_string,
          py_object);

      Py_DECREF(py_object);
    }
  }

  return py_dict;
}


static int handle_import_module(
    YR_MODULE_IMPORT* module_import,
    CALLBACK_DATA* data)
{
  if (data->modules_data == NULL)
    return CALLBACK_CONTINUE;

  PyGILState_STATE gil_state = PyGILState_Ensure();

  PyObject* module_data = PyDict_GetItemString(
      data->modules_data,
      module_import->module_name);

  #if PY_MAJOR_VERSION >= 3
  if (module_data != NULL && PyBytes_Check(module_data))
  #else
  if (module_data != NULL && PyString_Check(module_data))
  #endif
  {
    Py_ssize_t data_size;

    #if PY_MAJOR_VERSION >= 3
    PyBytes_AsStringAndSize(
        module_data,
        (char**) &module_import->module_data,
        &data_size);
    #else
    PyString_AsStringAndSize(
        module_data,
        (char**) &module_import->module_data,
        &data_size);
    #endif

    module_import->module_data_size = data_size;
  }

  PyGILState_Release(gil_state);

  return CALLBACK_CONTINUE;
}


static int handle_module_imported(
    void* message_data,
    CALLBACK_DATA* data)
{
  if (data->modules_callback == NULL)
    return CALLBACK_CONTINUE;

  PyGILState_STATE gil_state = PyGILState_Ensure();

  PyObject* module_info_dict = convert_structure_to_python(
      object_as_structure(message_data));

  if (module_info_dict == NULL)
  {
    PyGILState_Release(gil_state);
    return CALLBACK_CONTINUE;
  }

  PyObject* object = PY_STRING(object_as_structure(message_data)->identifier);
  PyDict_SetItemString(module_info_dict, "module", object);
  Py_DECREF(object);

  Py_INCREF(data->modules_callback);

  PyObject* callback_result = PyObject_CallFunctionObjArgs(
      data->modules_callback,
      module_info_dict,
      NULL);

  int result = CALLBACK_CONTINUE;

  if (callback_result != NULL)
  {
    #if PY_MAJOR_VERSION >= 3
    if (PyLong_Check(callback_result))
    #else
    if (PyLong_Check(callback_result) || PyInt_Check(callback_result))
    #endif
    {
      result = (int) PyLong_AsLong(callback_result);
    }
  }
  else
  {
    result = CALLBACK_ERROR;
  }

  Py_XDECREF(callback_result);
  Py_DECREF(module_info_dict);
  Py_DECREF(data->modules_callback);

  PyGILState_Release(gil_state);

  return result;
}


static int handle_too_many_matches(
    YR_SCAN_CONTEXT* context,
    YR_STRING* string,
    CALLBACK_DATA* data)
{
  PyGILState_STATE gil_state = PyGILState_Ensure();

  PyObject* warning_type = NULL;
  PyObject* identifier = NULL;

  int result = CALLBACK_CONTINUE;

  if (data->warnings_callback == NULL)
  {
    char message[200];

    snprintf(
        message,
        sizeof(message),
        "too many matches for string %s in rule \"%s\"",
        string->identifier,
        context->rules->rules_table[string->rule_idx].identifier);

    if (PyErr_WarnEx(PyExc_RuntimeWarning, message, 1) == -1)
      result = CALLBACK_ERROR;
  }
  else
  {
    Py_INCREF(data->warnings_callback);

    identifier = PyBytes_FromString(string->identifier);

    if (identifier == NULL)
    {
      result = CALLBACK_ERROR;
      goto _exit;
    }

    warning_type = PyLong_FromLong(CALLBACK_MSG_TOO_MANY_MATCHES);

    if (warning_type == NULL)
    {
      result = CALLBACK_ERROR;
      goto _exit;
    }

    PyObject* callback_result = PyObject_CallFunctionObjArgs(
        data->warnings_callback,
        warning_type,
        identifier,
        NULL);

    if (callback_result != NULL)
    {
      #if PY_MAJOR_VERSION >= 3
      if (PyLong_Check(callback_result))
      #else
      if (PyLong_Check(callback_result) || PyInt_Check(callback_result))
      #endif
      {
        result = (int) PyLong_AsLong(callback_result);
      }
    }
    else
    {
      result = CALLBACK_ERROR;
    }

    Py_XDECREF(callback_result);
  }

_exit:

  Py_XDECREF(identifier);
  Py_XDECREF(warning_type);
  Py_XDECREF(data->warnings_callback);

  PyGILState_Release(gil_state);

  return result;
}


#define CALLBACK_MATCHES 0x01
#define CALLBACK_NON_MATCHES 0x02
#define CALLBACK_ALL CALLBACK_MATCHES | CALLBACK_NON_MATCHES


int yara_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  YR_STRING* string;
  YR_MATCH* m;
  YR_META* meta;
  YR_RULE* rule;

  const char* tag;

  PyObject* tag_list = NULL;
  PyObject* string_list = NULL;
  PyObject* meta_list = NULL;
  PyObject* match;
  PyObject* callback_dict;
  PyObject* object;
  PyObject* tuple;
  PyObject* matches = ((CALLBACK_DATA*) user_data)->matches;
  PyObject* callback = ((CALLBACK_DATA*) user_data)->callback;
  PyObject* callback_result;

  int which = ((CALLBACK_DATA*) user_data)->which;

  switch(message)
  {
  case CALLBACK_MSG_IMPORT_MODULE:
    return handle_import_module(message_data, user_data);

  case CALLBACK_MSG_MODULE_IMPORTED:
    return handle_module_imported(message_data, user_data);

  case CALLBACK_MSG_TOO_MANY_MATCHES:
    return handle_too_many_matches(context, message_data, user_data);

  case CALLBACK_MSG_SCAN_FINISHED:
    return CALLBACK_CONTINUE;

  case CALLBACK_MSG_RULE_NOT_MATCHING:
    // In cases where the rule doesn't match and the user didn't provided a
    // callback function or is not interested in getting notified about
    // non-matches, there's nothing more do to here, keep executing the function
    // if otherwise.

    if (callback == NULL ||
        (which & CALLBACK_NON_MATCHES) != CALLBACK_NON_MATCHES)
      return CALLBACK_CONTINUE;
  }

  // At this point we have handled all the other cases of when this callback
  // can be called. The only things left are:
  //
  // 1. A matching rule.
  //
  // 2 A non-matching rule and the user has requested to see non-matching rules.
  //
  // In both cases, we need to create the data that will be either passed back
  // to the python callback or stored in the matches list.

  int result = CALLBACK_CONTINUE;

  rule = (YR_RULE*) message_data;

  PyGILState_STATE gil_state = PyGILState_Ensure();

  tag_list = PyList_New(0);
  string_list = PyList_New(0);
  meta_list = PyDict_New();

  if (tag_list == NULL || string_list == NULL || meta_list == NULL)
  {
    Py_XDECREF(tag_list);
    Py_XDECREF(string_list);
    Py_XDECREF(meta_list);
    PyGILState_Release(gil_state);

    return CALLBACK_ERROR;
  }

  yr_rule_tags_foreach(rule, tag)
  {
    object = PY_STRING(tag);
    PyList_Append(tag_list, object);
    Py_DECREF(object);
  }

  yr_rule_metas_foreach(rule, meta)
  {
    if (meta->type == META_TYPE_INTEGER)
      object = Py_BuildValue("i", meta->integer);
    else if (meta->type == META_TYPE_BOOLEAN)
      object = PyBool_FromLong((long) meta->integer);
    else
      object = PY_STRING(meta->string);

    PyDict_SetItemString(meta_list, meta->identifier, object);
    Py_DECREF(object);
  }

  yr_rule_strings_foreach(rule, string)
  {
    yr_string_matches_foreach(context, string, m)
    {
      object = PyBytes_FromStringAndSize((char*) m->data, m->data_length);

      tuple = Py_BuildValue(
          "(L,s,O)",
          m->base + m->offset,
          string->identifier,
          object);

      PyList_Append(string_list, tuple);

      Py_DECREF(object);
      Py_DECREF(tuple);
    }
  }

  if (message == CALLBACK_MSG_RULE_MATCHING)
  {
    match = Match_NEW(
        rule->identifier,
        rule->ns->name,
        tag_list,
        meta_list,
        string_list);

    if (match != NULL)
    {
      PyList_Append(matches, match);
      Py_DECREF(match);
    }
    else
    {
      Py_DECREF(tag_list);
      Py_DECREF(string_list);
      Py_DECREF(meta_list);
      PyGILState_Release(gil_state);

      return CALLBACK_ERROR;
    }
  }

  if (callback != NULL &&
      ((message == CALLBACK_MSG_RULE_MATCHING && (which & CALLBACK_MATCHES)) ||
       (message == CALLBACK_MSG_RULE_NOT_MATCHING && (which & CALLBACK_NON_MATCHES))))
  {
    Py_INCREF(callback);

    callback_dict = PyDict_New();

    object = PyBool_FromLong(message == CALLBACK_MSG_RULE_MATCHING);
    PyDict_SetItemString(callback_dict, "matches", object);
    Py_DECREF(object);

    object = PY_STRING(rule->identifier);
    PyDict_SetItemString(callback_dict, "rule", object);
    Py_DECREF(object);

    object = PY_STRING(rule->ns->name);
    PyDict_SetItemString(callback_dict, "namespace", object);
    Py_DECREF(object);

    PyDict_SetItemString(callback_dict, "tags", tag_list);
    PyDict_SetItemString(callback_dict, "meta", meta_list);
    PyDict_SetItemString(callback_dict, "strings", string_list);

    callback_result = PyObject_CallFunctionObjArgs(
        callback,
        callback_dict,
        NULL);

    if (callback_result != NULL)
    {
      #if PY_MAJOR_VERSION >= 3
      if (PyLong_Check(callback_result))
      #else
      if (PyLong_Check(callback_result) || PyInt_Check(callback_result))
      #endif
      {
        result = (int) PyLong_AsLong(callback_result);
      }

      Py_DECREF(callback_result);
    }
    else
    {
      result = CALLBACK_ERROR;
    }

    Py_DECREF(callback_dict);
    Py_DECREF(callback);
  }

  Py_DECREF(tag_list);
  Py_DECREF(string_list);
  Py_DECREF(meta_list);
  PyGILState_Release(gil_state);

  return result;
}


/* YR_STREAM read method for "file-like objects" */

static size_t flo_read(
    void* ptr,
    size_t size,
    size_t count,
    void* user_data)
{
  size_t i;

  for (i = 0; i < count; i++)
  {
    PyGILState_STATE gil_state = PyGILState_Ensure();

    PyObject* bytes = PyObject_CallMethod(
        (PyObject*) user_data, "read", "n", (Py_ssize_t) size);

    PyGILState_Release(gil_state);

    if (bytes != NULL)
    {
      Py_ssize_t len;
      char* buffer;

      int result = PyBytes_AsStringAndSize(bytes, &buffer, &len);

      if (result == -1 || (size_t) len < size)
      {
        Py_DECREF(bytes);
        return i;
      }

      memcpy((char*) ptr + i * size, buffer, size);

      Py_DECREF(bytes);
    }
    else
    {
      return i;
    }
  }

  return count;
}


/* YR_STREAM write method for "file-like objects" */

static size_t flo_write(
    const void* ptr,
    size_t size,
    size_t count,
    void* user_data)
{
  size_t i;

  for (i = 0; i < count; i++)
  {
    PyGILState_STATE gil_state = PyGILState_Ensure();

    PyObject* result = PyObject_CallMethod(
    #if PY_MAJOR_VERSION >= 3
        (PyObject*) user_data, "write", "y#", (char*) ptr + i * size, size);
    #else
        (PyObject*) user_data, "write", "s#", (char*) ptr + i * size, size);
    #endif

    PyGILState_Release(gil_state);

    if (result == NULL)
      return i;

    Py_DECREF(result);
  }

  return count;
}


PyObject* handle_error(
    int error,
    char* extra)
{
  switch(error)
  {
    case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
      return PyErr_Format(
          YaraError,
          "access denied");
    case ERROR_INSUFFICIENT_MEMORY:
      return PyErr_NoMemory();
    case ERROR_COULD_NOT_OPEN_FILE:
      return PyErr_Format(
          YaraError,
          "could not open file \"%s\"",
          extra);
    case ERROR_COULD_NOT_MAP_FILE:
      return PyErr_Format(
          YaraError,
          "could not map file \"%s\" into memory",
          extra);
    case ERROR_INVALID_FILE:
      return PyErr_Format(
          YaraError,
          "invalid rules file \"%s\"",
          extra);
    case ERROR_CORRUPT_FILE:
      return PyErr_Format(
          YaraError,
          "corrupt rules file \"%s\"",
          extra);
    case ERROR_SCAN_TIMEOUT:
      return PyErr_Format(
          YaraTimeoutError,
          "scanning timed out");
    case ERROR_INVALID_EXTERNAL_VARIABLE_TYPE:
      return PyErr_Format(
          YaraError,
          "external variable \"%s\" was already defined with a different type",
          extra);
    case ERROR_UNSUPPORTED_FILE_VERSION:
      return PyErr_Format(
          YaraError,
          "rules file \"%s\" is incompatible with this version of YARA",
          extra);
    default:
      return PyErr_Format(
          YaraError,
          "internal error: %d",
          error);
  }
}


int process_compile_externals(
    PyObject* externals,
    YR_COMPILER* compiler)
{
  PyObject* key;
  PyObject* value;
  Py_ssize_t pos = 0;

  char* identifier = NULL;
  int result;

  while (PyDict_Next(externals, &pos, &key, &value))
  {
    identifier = PY_STRING_TO_C(key);

    if (PyBool_Check(value))
    {
      result = yr_compiler_define_boolean_variable(
          compiler,
          identifier,
          PyObject_IsTrue(value));
    }
#if PY_MAJOR_VERSION >= 3
    else if (PyLong_Check(value))
#else
    else if (PyLong_Check(value) || PyInt_Check(value))
#endif
    {
      result = yr_compiler_define_integer_variable(
          compiler,
          identifier,
          PyLong_AsLongLong(value));
    }
    else if (PyFloat_Check(value))
    {
      result = yr_compiler_define_float_variable(
          compiler,
          identifier,
          PyFloat_AsDouble(value));
    }
    else if (PY_STRING_CHECK(value))
    {
      char* str = PY_STRING_TO_C(value);

      if (str == NULL)
        return ERROR_INVALID_ARGUMENT;

      result = yr_compiler_define_string_variable(
          compiler, identifier, str);
    }
    else
    {
      PyErr_Format(
          PyExc_TypeError,
          "external values must be of type integer, float, boolean or string");

      return ERROR_INVALID_ARGUMENT;
    }

    if (result != ERROR_SUCCESS)
    {
      handle_error(result, identifier);
      return result;
    }
  }

  return ERROR_SUCCESS;
}


int process_match_externals(
    PyObject* externals,
    YR_RULES* rules)
{
  PyObject* key;
  PyObject* value;
  Py_ssize_t pos = 0;

  char* identifier = NULL;
  int result;

  while (PyDict_Next(externals, &pos, &key, &value))
  {
    identifier = PY_STRING_TO_C(key);

    if (PyBool_Check(value))
    {
      result = yr_rules_define_boolean_variable(
          rules,
          identifier,
          PyObject_IsTrue(value));
    }
#if PY_MAJOR_VERSION >= 3
    else if (PyLong_Check(value))
#else
    else if (PyLong_Check(value) || PyInt_Check(value))
#endif
    {
      result = yr_rules_define_integer_variable(
          rules,
          identifier,
          PyLong_AsLongLong(value));
    }
    else if (PyFloat_Check(value))
    {
      result = yr_rules_define_float_variable(
          rules,
          identifier,
          PyFloat_AsDouble(value));
    }
    else if (PY_STRING_CHECK(value))
    {
      char* str = PY_STRING_TO_C(value);

      if (str == NULL)
        return ERROR_INVALID_ARGUMENT;

      result = yr_rules_define_string_variable(
          rules, identifier, str);
    }
    else
    {
      PyErr_Format(
          PyExc_TypeError,
          "external values must be of type integer, float, boolean or string");

      return ERROR_INVALID_ARGUMENT;
    }

    // yr_rules_define_xxx_variable returns ERROR_INVALID_ARGUMENT if the
    // variable wasn't previously defined in the compilation phase. Ignore
    // those errors because we don't want the "scan" method being aborted
    // because of the "externals" dictionary having more keys than those used
    // during compilation.

    if (result != ERROR_SUCCESS &&
        result != ERROR_INVALID_ARGUMENT)
    {
      handle_error(result, identifier);
      return result;
    }
  }

  return ERROR_SUCCESS;
}


static PyObject* Match_NEW(
    const char* rule,
    const char* ns,
    PyObject* tags,
    PyObject* meta,
    PyObject* strings)
{
  Match* object = PyObject_NEW(Match, &Match_Type);

  if (object != NULL)
  {
    object->rule = PY_STRING(rule);
    object->ns = PY_STRING(ns);
    object->tags = tags;
    object->meta = meta;
    object->strings = strings;

    Py_INCREF(tags);
    Py_INCREF(meta);
    Py_INCREF(strings);
  }

  return (PyObject*) object;
}


static void Match_dealloc(
    PyObject* self)
{
  Match* object = (Match*) self;

  Py_DECREF(object->rule);
  Py_DECREF(object->ns);
  Py_DECREF(object->tags);
  Py_DECREF(object->meta);
  Py_DECREF(object->strings);

  PyObject_Del(self);
}


static PyObject* Match_repr(
    PyObject* self)
{
  Match* object = (Match*) self;
  Py_INCREF(object->rule);
  return object->rule;
}


static PyObject* Match_getattro(
    PyObject* self,
    PyObject* name)
{
  return PyObject_GenericGetAttr(self, name);
}


static PyObject* Match_richcompare(
    PyObject* self,
    PyObject* other,
    int op)
{
  PyObject* result = NULL;

  Match* a = (Match*) self;
  Match* b = (Match*) other;

  if(PyObject_TypeCheck(other, &Match_Type))
  {
    switch(op)
    {
    case Py_EQ:
      if (PyObject_RichCompareBool(a->rule, b->rule, Py_EQ) &&
          PyObject_RichCompareBool(a->ns, b->ns, Py_EQ))
        result = Py_True;
      else
        result = Py_False;

      Py_INCREF(result);
      break;

    case Py_NE:
      if (PyObject_RichCompareBool(a->rule, b->rule, Py_NE) ||
          PyObject_RichCompareBool(a->ns, b->ns, Py_NE))
          result = Py_True;
      else
          result = Py_False;

      Py_INCREF(result);
      break;

    case Py_LT:
    case Py_LE:
    case Py_GT:
    case Py_GE:
      if (PyObject_RichCompareBool(a->rule, b->rule, Py_EQ))
        result = PyObject_RichCompare(a->ns, b->ns, op);
      else
        result = PyObject_RichCompare(a->rule, b->rule, op);

      break;
    }
  }
  else
  {
    result = PyErr_Format(
        PyExc_TypeError,
        "'Match' objects must be compared with objects of the same class");
  }

  return result;
}


static Py_hash_t Match_hash(
    PyObject* self)
{
  Match* match = (Match*) self;
  return PyObject_Hash(match->rule) + PyObject_Hash(match->ns);
}

////////////////////////////////////////////////////////////////////////////////


static void Rule_dealloc(
    PyObject* self)
{
  Rule* object = (Rule*) self;
  Py_XDECREF(object->identifier);
  Py_XDECREF(object->tags);
  Py_XDECREF(object->meta);
  Py_XDECREF(object->global);
  Py_XDECREF(object->private);
  PyObject_Del(self);
}

static PyObject* Rule_getattro(
    PyObject* self,
    PyObject* name)
{
  return PyObject_GenericGetAttr(self, name);
}


static Rules* Rules_NEW(void)
{
  Rules* rules = PyObject_NEW(Rules, &Rules_Type);

  if (rules != NULL)
  {
    rules->rules = NULL;
    rules->externals = NULL;
  }

  return rules;
}

static void Rules_dealloc(
    PyObject* self)
{
  Rules* object = (Rules*) self;

  Py_XDECREF(object->externals);

  if (object->rules != NULL)
    yr_rules_destroy(object->rules);

  PyObject_Del(self);
}

static PyObject* Rules_next(
    PyObject* self)
{
  PyObject* tag_list;
  PyObject* object;
  PyObject* meta_list;

  YR_META* meta;
  const char* tag;

  Rule* rule;
  Rules* rules = (Rules *) self;

  // Generate new Rule object based upon iter_current_rule and increment
  // iter_current_rule.

  if (RULE_IS_NULL(rules->iter_current_rule))
  {
    rules->iter_current_rule = rules->rules->rules_table;
    PyErr_SetNone(PyExc_StopIteration);
    return NULL;
  }

  rule = PyObject_NEW(Rule, &Rule_Type);
  tag_list = PyList_New(0);
  meta_list = PyDict_New();

  if (rule != NULL && tag_list != NULL && meta_list != NULL)
  {
    yr_rule_tags_foreach(rules->iter_current_rule, tag)
    {
      object = PY_STRING(tag);
      PyList_Append(tag_list, object);
      Py_DECREF(object);
    }

    yr_rule_metas_foreach(rules->iter_current_rule, meta)
    {
      if (meta->type == META_TYPE_INTEGER)
        object = Py_BuildValue("i", meta->integer);
      else if (meta->type == META_TYPE_BOOLEAN)
        object = PyBool_FromLong((long) meta->integer);
      else
        object = PY_STRING(meta->string);

      PyDict_SetItemString(meta_list, meta->identifier, object);
      Py_DECREF(object);
    }

    rule->global = PyBool_FromLong(rules->iter_current_rule->flags & RULE_FLAGS_GLOBAL);
    rule->private = PyBool_FromLong(rules->iter_current_rule->flags & RULE_FLAGS_PRIVATE);
    rule->identifier = PY_STRING(rules->iter_current_rule->identifier);
    rule->tags = tag_list;
    rule->meta = meta_list;
    rules->iter_current_rule++;
    return (PyObject*) rule;
  }
  else
  {
    Py_XDECREF(tag_list);
    Py_XDECREF(meta_list);
    return PyErr_Format(PyExc_TypeError, "Out of memory");
  }
}

static PyObject* Rules_match(
    PyObject* self,
    PyObject* args,
    PyObject* keywords)
{
  static char* kwlist[] = {
      "filepath", "pid", "data", "externals",
      "callback", "fast", "timeout", "modules_data",
      "modules_callback", "which_callbacks", "warnings_callback", NULL
      };

  char* filepath = NULL;
  Py_buffer data = {0};

  int pid = -1;
  int timeout = 0;
  int error = ERROR_SUCCESS;
  int fast_mode = 0;

  PyObject* externals = NULL;
  PyObject* fast = NULL;

  Rules* object = (Rules*) self;

  CALLBACK_DATA callback_data;

  callback_data.matches = NULL;
  callback_data.callback = NULL;
  callback_data.modules_data = NULL;
  callback_data.modules_callback = NULL;
  callback_data.warnings_callback = NULL;
  callback_data.which = CALLBACK_ALL;

  if (PyArg_ParseTupleAndKeywords(
        args,
        keywords,
        "|sis*OOOiOOiO",
        kwlist,
        &filepath,
        &pid,
        &data,
        &externals,
        &callback_data.callback,
        &fast,
        &timeout,
        &callback_data.modules_data,
        &callback_data.modules_callback,
        &callback_data.which,
        &callback_data.warnings_callback))
  {
    if (filepath == NULL && data.buf == NULL && pid == -1)
    {
      return PyErr_Format(
          PyExc_TypeError,
          "match() takes at least one argument");
    }

    if (callback_data.callback != NULL)
    {
      if (!PyCallable_Check(callback_data.callback))
      {
        PyBuffer_Release(&data);
        return PyErr_Format(
            PyExc_TypeError,
            "'callback' must be callable");
      }
    }

    if (callback_data.modules_callback != NULL)
    {
      if (!PyCallable_Check(callback_data.modules_callback))
      {
        PyBuffer_Release(&data);
        return PyErr_Format(
            PyExc_TypeError,
            "'modules_callback' must be callable");
      }
    }

    if (callback_data.warnings_callback != NULL)
    {
      if (!PyCallable_Check(callback_data.warnings_callback))
      {
        PyBuffer_Release(&data);
        return PyErr_Format(
            PyExc_TypeError,
            "'warnings_callback' must be callable");
      }
    }

    if (callback_data.modules_data != NULL)
    {
      if (!PyDict_Check(callback_data.modules_data))
      {
        PyBuffer_Release(&data);
        return PyErr_Format(
            PyExc_TypeError,
            "'modules_data' must be a dictionary");
      }
    }

    if (externals != NULL && externals != Py_None)
    {
      if (PyDict_Check(externals))
      {
        if (process_match_externals(externals, object->rules) != ERROR_SUCCESS)
        {
          // Restore original externals provided during compiling.
          process_match_externals(object->externals, object->rules);

          PyBuffer_Release(&data);
          return NULL;
        }
      }
      else
      {
        PyBuffer_Release(&data);
        return PyErr_Format(
            PyExc_TypeError,
            "'externals' must be a dictionary");
      }
    }

    if (fast != NULL)
    {
      fast_mode = (PyObject_IsTrue(fast) == 1);
    }

    if (filepath != NULL)
    {
      callback_data.matches = PyList_New(0);

      Py_BEGIN_ALLOW_THREADS

      error = yr_rules_scan_file(
          object->rules,
          filepath,
          fast_mode ? SCAN_FLAGS_FAST_MODE : 0,
          yara_callback,
          &callback_data,
          timeout);

      Py_END_ALLOW_THREADS
    }
    else if (data.buf != NULL)
    {
      callback_data.matches = PyList_New(0);

      Py_BEGIN_ALLOW_THREADS

      error = yr_rules_scan_mem(
          object->rules,
          (unsigned char*) data.buf,
          (size_t) data.len,
          fast_mode ? SCAN_FLAGS_FAST_MODE : 0,
          yara_callback,
          &callback_data,
          timeout);

      Py_END_ALLOW_THREADS
    }
    else if (pid != -1)
    {
      callback_data.matches = PyList_New(0);

      Py_BEGIN_ALLOW_THREADS

      error = yr_rules_scan_proc(
          object->rules,
          pid,
          fast_mode ? SCAN_FLAGS_FAST_MODE : 0,
          yara_callback,
          &callback_data,
          timeout);

      Py_END_ALLOW_THREADS
    }

    PyBuffer_Release(&data);

    // Restore original externals provided during compiling.
    if (object->externals != NULL)
    {
      if (process_match_externals(
            object->externals, object->rules) != ERROR_SUCCESS)
      {
        Py_DECREF(callback_data.matches);
        return NULL;
      }
    }

    if (error != ERROR_SUCCESS)
    {
      Py_DECREF(callback_data.matches);

      if (error != ERROR_CALLBACK_ERROR)
      {
        if (filepath != NULL)
        {
          handle_error(error, filepath);
        }
        else if (pid != -1)
        {
          handle_error(error, "<proc>");
        }
        else
        {
          handle_error(error, "<data>");
        }

        #ifdef PROFILING_ENABLED
        PyObject* exception = PyErr_Occurred();

        if (exception != NULL && error == ERROR_SCAN_TIMEOUT)
        {
          PyObject_SetAttrString(
              exception,
              "profiling_info",
              Rules_profiling_info(self, NULL));
        }
        #endif
      }

      return NULL;
    }
  }

  return callback_data.matches;
}


static PyObject* Rules_save(
    PyObject* self,
    PyObject* args,
    PyObject* keywords)
{
  static char* kwlist[] = {
      "filepath", "file",  NULL
      };

  char* filepath = NULL;
  PyObject* file = NULL;
  Rules* rules = (Rules*) self;

  int error;

  if (!PyArg_ParseTupleAndKeywords(
      args,
      keywords,
      "|sO",
      kwlist,
      &filepath,
      &file))
  {
    return NULL;
  }

  if (filepath != NULL)
  {
    Py_BEGIN_ALLOW_THREADS
    error = yr_rules_save(rules->rules, filepath);
    Py_END_ALLOW_THREADS

    if (error != ERROR_SUCCESS)
      return handle_error(error, filepath);
  }
  else if (file != NULL && PyObject_HasAttrString(file, "write"))
  {
    YR_STREAM stream;

    stream.user_data = file;
    stream.write = flo_write;

    Py_BEGIN_ALLOW_THREADS;
    error = yr_rules_save_stream(rules->rules, &stream);
    Py_END_ALLOW_THREADS;

    if (error != ERROR_SUCCESS)
      return handle_error(error, "<file-like-object>");
  }
  else
  {
    return PyErr_Format(
      PyExc_TypeError,
      "load() expects either a file path or a file-like object");
  }

  Py_RETURN_NONE;
}


static PyObject* Rules_profiling_info(
    PyObject* self,
    PyObject* args)
{

#ifdef PROFILING_ENABLED
  PyObject* object;
  PyObject* result;

  YR_RULES* rules = ((Rules*) self)->rules;
  YR_RULE* rule;
  YR_STRING* string;

  char key[512];
  uint64_t clock_ticks;

  result = PyDict_New();

  yr_rules_foreach(rules, rule)
  {
    clock_ticks = rule->clock_ticks;

    yr_rule_strings_foreach(rule, string)
    {
      clock_ticks += string->clock_ticks;
    }

    snprintf(key, sizeof(key), "%s:%s", rule->ns->name, rule->identifier);

    object = PyLong_FromLongLong(clock_ticks);
    PyDict_SetItemString(result, key, object);
    Py_DECREF(object);
  }

  return result;
#else
  return PyErr_Format(YaraError, "libyara compiled without profiling support");
#endif
}


static PyObject* Rules_getattro(
    PyObject* self,
    PyObject* name)
{
  return PyObject_GenericGetAttr(self, name);
}


void raise_exception_on_error(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data)
{
  if (error_level == YARA_ERROR_LEVEL_ERROR)
  {
    if (file_name != NULL)
      PyErr_Format(
          YaraSyntaxError,
          "%s(%d): %s",
          file_name,
          line_number,
          message);
    else
      PyErr_Format(
          YaraSyntaxError,
          "line %d: %s",
          line_number,
          message);
  }
  else
  {
    PyObject* warnings = (PyObject*)user_data;
    PyObject* warning_msg;
    if (file_name != NULL)
      warning_msg = PY_STRING_FORMAT(
          "%s(%d): %s",
          file_name,
          line_number,
          message);
    else
      warning_msg = PY_STRING_FORMAT(
          "line %d: %s",
          line_number,
          message);
    PyList_Append(warnings, warning_msg);
    Py_DECREF(warning_msg);
  }
}


////////////////////////////////////////////////////////////////////////////////

const char* yara_include_callback(
    const char* include_name,
    const char* calling_rule_filename,
    const char* calling_rule_namespace,
    void* user_data)
{
  PyObject* result;
  PyObject* callback = (PyObject*) user_data;
  PyObject* py_incl_name = NULL;
  PyObject* py_calling_fn = NULL;
  PyObject* py_calling_ns = NULL;
  PyObject* type = NULL;
  PyObject* value = NULL;
  PyObject* traceback = NULL;

  const char* cstring_result = NULL;

  PyGILState_STATE gil_state = PyGILState_Ensure();

  if (include_name != NULL)
  {
    py_incl_name = PY_STRING(include_name);
  }
  else //safeguard: should never happen for 'include_name'
  {
    py_incl_name = Py_None;
    Py_INCREF(py_incl_name);
  }

  if (calling_rule_filename != NULL)
  {
    py_calling_fn = PY_STRING(calling_rule_filename);
  }
  else
  {
    py_calling_fn = Py_None;
    Py_INCREF(py_calling_fn);
  }

  if (calling_rule_namespace != NULL)
  {
    py_calling_ns = PY_STRING(calling_rule_namespace);
  }
  else
  {
    py_calling_ns = Py_None;
    Py_INCREF(py_calling_ns);
  }

  PyErr_Fetch(&type, &value, &traceback);

  result = PyObject_CallFunctionObjArgs(
      callback,
      py_incl_name,
      py_calling_fn,
      py_calling_ns,
      NULL);

  PyErr_Restore(type, value, traceback);

  Py_DECREF(py_incl_name);
  Py_DECREF(py_calling_fn);
  Py_DECREF(py_calling_ns);

  if (result != NULL && result != Py_None && PY_STRING_CHECK(result))
  {
    //transferring string ownership to C code
    cstring_result = strdup(PY_STRING_TO_C(result));
  }
  else
  {
    if (PyErr_Occurred() == NULL)
    {
      PyErr_Format(PyExc_TypeError,
          "'include_callback' function must return a yara rules as an ascii "
          "or unicode string");
    }
  }

  Py_XDECREF(result);
  PyGILState_Release(gil_state);

  return cstring_result;
}

void yara_include_free(
    const char* result_ptr,
    void* user_data)
{
  if (result_ptr != NULL)
  {
    free((void*) result_ptr);
  }
}

////////////////////////////////////////////////////////////////////////////////

static PyObject* yara_set_config(
    PyObject* self,
    PyObject* args,
    PyObject* keywords)
{

  /*
   * It is recommended that this be kept up to date with the config
   * options present in yara/libyara.c yr_set_configuration(...) - ck
   */
  static char *kwlist[] = {
    "stack_size", "max_strings_per_rule", "max_match_data", NULL};

  unsigned int stack_size = 0;
  unsigned int max_strings_per_rule = 0;
  unsigned int max_match_data = 0;

  int error = 0;

  if (PyArg_ParseTupleAndKeywords(
        args,
        keywords,
        "|III",
        kwlist,
        &stack_size,
        &max_strings_per_rule,
  	&max_match_data))
  {
    if (stack_size != 0)
    {
      error = yr_set_configuration(
          YR_CONFIG_STACK_SIZE,
          &stack_size);

      if ( error != ERROR_SUCCESS)
        return handle_error(error, NULL);
    }

    if (max_strings_per_rule != 0)
    {
      error = yr_set_configuration(
          YR_CONFIG_MAX_STRINGS_PER_RULE,
				  &max_strings_per_rule);

      if (error != ERROR_SUCCESS)
        return handle_error(error, NULL);
    }

    if (max_match_data != 0)
    {
      error = yr_set_configuration(
          YR_CONFIG_MAX_MATCH_DATA,
				  &max_match_data);

      if (error != ERROR_SUCCESS)
        return handle_error(error, NULL);
    }
  }

  Py_RETURN_NONE;
}

static PyObject* yara_compile(
    PyObject* self,
    PyObject* args,
    PyObject* keywords)
{
  static char *kwlist[] = {
    "filepath", "source", "file", "filepaths", "sources",
    "includes", "externals", "error_on_warning", "include_callback", NULL};

  YR_COMPILER* compiler;
  YR_RULES* yara_rules;
  FILE* fh;

  Rules* rules;

  PyObject* key;
  PyObject* value;
  PyObject* result = NULL;
  PyObject* file = NULL;
  PyObject* sources_dict = NULL;
  PyObject* filepaths_dict = NULL;
  PyObject* includes = NULL;
  PyObject* externals = NULL;
  PyObject* error_on_warning = NULL;
  PyObject* include_callback = NULL;

  Py_ssize_t pos = 0;

  int fd;
  int error = 0;

  char* filepath = NULL;
  char* source = NULL;
  char* ns = NULL;
  PyObject* warnings = PyList_New(0);
  bool warning_error = false;

  if (PyArg_ParseTupleAndKeywords(
        args,
        keywords,
        "|ssOOOOOOO",
        kwlist,
        &filepath,
        &source,
        &file,
        &filepaths_dict,
        &sources_dict,
        &includes,
        &externals,
        &error_on_warning,
        &include_callback))
  {

    error = yr_compiler_create(&compiler);

    if (error != ERROR_SUCCESS)
      return handle_error(error, NULL);

    yr_compiler_set_callback(compiler, raise_exception_on_error, warnings);

    if (error_on_warning != NULL)
    {
      if (PyBool_Check(error_on_warning))
      {
        if (PyObject_IsTrue(error_on_warning) == 1)
        {
          warning_error = true;
        }
      }
      else
      {
        yr_compiler_destroy(compiler);
        return PyErr_Format(
            PyExc_TypeError,
            "'error_on_warning' param must be of boolean type");
      }
    }

    if (includes != NULL)
    {
      if (PyBool_Check(includes))
      {
        // PyObject_IsTrue can return -1 in case of error
        if (PyObject_IsTrue(includes) == 0)
          yr_compiler_set_include_callback(compiler, NULL, NULL, NULL);
      }
      else
      {
        yr_compiler_destroy(compiler);
        return PyErr_Format(
            PyExc_TypeError,
            "'includes' param must be of boolean type");
      }
    }

    if (include_callback != NULL)
    {
      if (!PyCallable_Check(include_callback))
      {
        yr_compiler_destroy(compiler);
        return PyErr_Format(
            PyExc_TypeError,
            "'include_callback' must be callable");
      }

      yr_compiler_set_include_callback(
          compiler,
          yara_include_callback,
          yara_include_free,
          include_callback);
    }

    if (externals != NULL && externals != Py_None)
    {
      if (PyDict_Check(externals))
      {
        if (process_compile_externals(externals, compiler) != ERROR_SUCCESS)
        {
          yr_compiler_destroy(compiler);
          return NULL;
        }
      }
      else
      {
        yr_compiler_destroy(compiler);
        return PyErr_Format(
            PyExc_TypeError,
            "'externals' must be a dictionary");
      }
    }

    Py_XINCREF(include_callback);

    if (filepath != NULL)
    {
      fh = fopen(filepath, "r");

      if (fh != NULL)
      {
        error = yr_compiler_add_file(compiler, fh, NULL, filepath);
        fclose(fh);
      }
      else
      {
        result = PyErr_SetFromErrno(YaraError);
      }
    }
    else if (source != NULL)
    {
      error = yr_compiler_add_string(compiler, source, NULL);
    }
    else if (file != NULL)
    {
      fd = dup(PyObject_AsFileDescriptor(file));

      if (fd != -1)
      {
        fh = fdopen(fd, "r");
        error = yr_compiler_add_file(compiler, fh, NULL, NULL);
        fclose(fh);
      }
      else
      {
        result = PyErr_Format(
            PyExc_TypeError,
            "'file' is not a file object");
      }
    }
    else if (sources_dict != NULL)
    {
      if (PyDict_Check(sources_dict))
      {
        while (PyDict_Next(sources_dict, &pos, &key, &value))
        {
          source = PY_STRING_TO_C(value);
          ns = PY_STRING_TO_C(key);

          if (source != NULL && ns != NULL)
          {
            error = yr_compiler_add_string(compiler, source, ns);

            if (error > 0)
              break;
          }
          else
          {
            result = PyErr_Format(
                PyExc_TypeError,
                "keys and values of the 'sources' dictionary must be "
                "of string type");
            break;
          }
        }
      }
      else
      {
        result = PyErr_Format(
            PyExc_TypeError,
            "'sources' must be a dictionary");
      }
    }
    else if (filepaths_dict != NULL)
    {
      if (PyDict_Check(filepaths_dict))
      {
        while (PyDict_Next(filepaths_dict, &pos, &key, &value))
        {
          filepath = PY_STRING_TO_C(value);
          ns = PY_STRING_TO_C(key);

          if (filepath != NULL && ns != NULL)
          {
            fh = fopen(filepath, "r");

            if (fh != NULL)
            {
              error = yr_compiler_add_file(compiler, fh, ns, filepath);
              fclose(fh);

              if (error > 0)
                break;
            }
            else
            {
              result = PyErr_SetFromErrno(YaraError);
              break;
            }
          }
          else
          {
            result = PyErr_Format(
                PyExc_TypeError,
                "keys and values of the filepaths dictionary must be of "
                "string type");
            break;
          }
        }
      }
      else
      {
        result = PyErr_Format(
            PyExc_TypeError,
            "filepaths must be a dictionary");
      }
    }
    else
    {
      result = PyErr_Format(
          PyExc_TypeError,
          "compile() takes 1 argument");
    }

    if (warning_error && PyList_Size(warnings) > 0)
    {
      PyErr_SetObject(YaraWarningError, warnings);
    }

    Py_DECREF(warnings);

    if (PyErr_Occurred() == NULL)
    {
      rules = Rules_NEW();

      if (rules != NULL)
      {
        Py_BEGIN_ALLOW_THREADS
        error = yr_compiler_get_rules(compiler, &yara_rules);
        Py_END_ALLOW_THREADS

        if (error == ERROR_SUCCESS)
        {
          rules->rules = yara_rules;
          rules->iter_current_rule = rules->rules->rules_table;

          if (externals != NULL && externals != Py_None)
            rules->externals = PyDict_Copy(externals);

          result = (PyObject*) rules;
        }
        else
        {
          Py_DECREF(rules);
          result = handle_error(error, NULL);
        }
      }
      else
      {
        result = handle_error(ERROR_INSUFFICIENT_MEMORY, NULL);
      }
    }

    yr_compiler_destroy(compiler);
    Py_XDECREF(include_callback);
  }

  return result;
}


static PyObject* yara_load(
    PyObject* self,
    PyObject* args,
    PyObject* keywords)
{
  static char* kwlist[] = {
      "filepath", "file",  NULL
      };

  YR_EXTERNAL_VARIABLE* external;

  Rules* rules = NULL;
  PyObject* file = NULL;
  char* filepath = NULL;

  int error;

  if (!PyArg_ParseTupleAndKeywords(
      args,
      keywords,
      "|sO",
      kwlist,
      &filepath,
      &file))
  {
    return NULL;
  }

  if (filepath != NULL)
  {
    rules = Rules_NEW();

    if (rules == NULL)
      return PyErr_NoMemory();

    Py_BEGIN_ALLOW_THREADS;
    error = yr_rules_load(filepath, &rules->rules);
    Py_END_ALLOW_THREADS;

    if (error != ERROR_SUCCESS)
    {
      Py_DECREF(rules);
      return handle_error(error, filepath);
    }
  }
  else if (file != NULL && PyObject_HasAttrString(file, "read"))
  {
    YR_STREAM stream;

    stream.user_data = file;
    stream.read = flo_read;

    rules = Rules_NEW();

    if (rules == NULL)
      return PyErr_NoMemory();

    Py_BEGIN_ALLOW_THREADS;
    error = yr_rules_load_stream(&stream, &rules->rules);
    Py_END_ALLOW_THREADS;

    if (error != ERROR_SUCCESS)
    {
      Py_DECREF(rules);
      return handle_error(error, "<file-like-object>");
    }
  }
  else
  {
    return PyErr_Format(
      PyExc_TypeError,
      "load() expects either a file path or a file-like object");
  }

  external = rules->rules->ext_vars_table;
  rules->iter_current_rule = rules->rules->rules_table;

  if (!EXTERNAL_VARIABLE_IS_NULL(external))
    rules->externals = PyDict_New();

  while (!EXTERNAL_VARIABLE_IS_NULL(external))
  {
    switch(external->type)
    {
      case EXTERNAL_VARIABLE_TYPE_BOOLEAN:
        PyDict_SetItemString(
            rules->externals,
            external->identifier,
            PyBool_FromLong((long) external->value.i));
        break;
      case EXTERNAL_VARIABLE_TYPE_INTEGER:
        PyDict_SetItemString(
            rules->externals,
            external->identifier,
            PyLong_FromLong((long) external->value.i));
        break;
      case EXTERNAL_VARIABLE_TYPE_FLOAT:
        PyDict_SetItemString(
            rules->externals,
            external->identifier,
            PyFloat_FromDouble(external->value.f));
        break;
      case EXTERNAL_VARIABLE_TYPE_STRING:
        PyDict_SetItemString(
            rules->externals,
            external->identifier,
            PY_STRING(external->value.s));
        break;
    }

    external++;
  }

  return (PyObject*) rules;
}


void finalize(void)
{
  yr_finalize();
}


static PyMethodDef yara_methods[] = {
  {
    "compile",
    (PyCFunction) yara_compile,
    METH_VARARGS | METH_KEYWORDS,
    "Compiles a YARA rules file and returns an instance of class Rules"
  },
  {
    "load",
    (PyCFunction) yara_load,
    METH_VARARGS | METH_KEYWORDS,
    "Loads a previously saved YARA rules file and returns an instance of class Rules"
  },
  {
    "set_config",
    (PyCFunction) yara_set_config,
    METH_VARARGS | METH_KEYWORDS,
    "Set a yara configuration variable (stack_size, max_strings_per_rule, or max_match_data)"
  },
  { NULL, NULL }
};

#if PY_MAJOR_VERSION >= 3
#define MOD_ERROR_VAL NULL
#define MOD_SUCCESS_VAL(val) val
#define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name(void)
#define MOD_DEF(ob, name, doc, methods) \
      static struct PyModuleDef moduledef = { \
        PyModuleDef_HEAD_INIT, name, doc, -1, methods, }; \
      ob = PyModule_Create(&moduledef);
#else
#define MOD_ERROR_VAL
#define MOD_SUCCESS_VAL(val)
#define MOD_INIT(name) void init##name(void)
#define MOD_DEF(ob, name, doc, methods) \
      ob = Py_InitModule3(name, methods, doc);
#endif

static PyObject* YaraWarningError_getwarnings(PyObject *self, void* closure)
{
  PyObject *args = PyObject_GetAttrString(self, "args");
  if (!args) {
    return NULL;
  }

  PyObject* ret = PyTuple_GetItem(args, 0);
  Py_XINCREF(ret);
  Py_XDECREF(args);
  return ret;
}

static PyGetSetDef YaraWarningError_getsetters[] = {
  {"warnings", YaraWarningError_getwarnings, NULL, NULL, NULL},
  {NULL}
};


MOD_INIT(yara)
{
  PyObject* m;

  MOD_DEF(m, "yara", YARA_DOC, yara_methods)

  if (m == NULL)
    return MOD_ERROR_VAL;

  /* initialize module variables/constants */

  PyModule_AddIntConstant(m, "CALLBACK_CONTINUE", 0);
  PyModule_AddIntConstant(m, "CALLBACK_ABORT", 1);
  PyModule_AddIntConstant(m, "CALLBACK_MATCHES", CALLBACK_MATCHES);
  PyModule_AddIntConstant(m, "CALLBACK_NON_MATCHES", CALLBACK_NON_MATCHES);
  PyModule_AddIntConstant(m, "CALLBACK_ALL", CALLBACK_ALL);
  PyModule_AddIntConstant(m, "CALLBACK_TOO_MANY_MATCHES", CALLBACK_MSG_TOO_MANY_MATCHES);
  PyModule_AddStringConstant(m, "__version__", YR_VERSION);
  PyModule_AddStringConstant(m, "YARA_VERSION", YR_VERSION);
  PyModule_AddIntConstant(m, "YARA_VERSION_HEX", YR_VERSION_HEX);

#if PYTHON_API_VERSION >= 1007
  YaraError = PyErr_NewException("yara.Error", PyExc_Exception, NULL);
  YaraSyntaxError = PyErr_NewException("yara.SyntaxError", YaraError, NULL);
  YaraTimeoutError = PyErr_NewException("yara.TimeoutError", YaraError, NULL);
  YaraWarningError = PyErr_NewException("yara.WarningError", YaraError, NULL);

  PyTypeObject *YaraWarningError_type = (PyTypeObject *) YaraWarningError;
  PyObject* descr = PyDescr_NewGetSet(YaraWarningError_type, YaraWarningError_getsetters);

  if (PyDict_SetItem(YaraWarningError_type->tp_dict, PyDescr_NAME(descr), descr) < 0)
  {
    Py_DECREF(m);
    Py_DECREF(descr);
  }

  Py_DECREF(descr);
#else
  YaraError = Py_BuildValue("s", "yara.Error");
  YaraSyntaxError = Py_BuildValue("s", "yara.SyntaxError");
  YaraTimeoutError = Py_BuildValue("s", "yara.TimeoutError");
  YaraWarningError = Py_BuildValue("s", "yara.WarningError");
#endif

  if (PyType_Ready(&Rule_Type) < 0)
    return MOD_ERROR_VAL;

  if (PyType_Ready(&Rules_Type) < 0)
    return MOD_ERROR_VAL;

  if (PyType_Ready(&Match_Type) < 0)
    return MOD_ERROR_VAL;

  PyModule_AddObject(m, "Rule", (PyObject*) &Rule_Type);
  PyModule_AddObject(m, "Rules", (PyObject*) &Rules_Type);
  PyModule_AddObject(m, "Match",  (PyObject*) &Match_Type);

  PyModule_AddObject(m, "Error", YaraError);
  PyModule_AddObject(m, "SyntaxError", YaraSyntaxError);
  PyModule_AddObject(m, "TimeoutError", YaraTimeoutError);
  PyModule_AddObject(m, "WarningError", YaraWarningError);

  if (yr_initialize() != ERROR_SUCCESS)
  {
    PyErr_SetString(YaraError, "initialization error");
    return MOD_ERROR_VAL;
  }

  Py_AtExit(finalize);

  return MOD_SUCCESS_VAL(m);
}
