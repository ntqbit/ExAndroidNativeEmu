import sqlite3
import verboselogs

from androidemu.java import JavaClassDef, JavaFieldDef, java_method_def
from androidemu.java.classes.string import String
from androidemu.java.classes.array import StringArray

from androidemu.java.classes.database import Cursor


logger = verboselogs.VerboseLogger(__name__)

OPEN_READWRITE = 0
OPEN_READONLY = 1


class SQLiteDatabase_CursorFactory(metaclass=JavaClassDef,
                                   jvm_name='android/database/sqlite/SQLiteDatabase$CursorFactory'):
    def __init__(self):
        pass


class SQLiteCursor(Cursor, metaclass=JavaClassDef,
                   jvm_name='android/database/sqlite/SQLiteCursor', jvm_super=Cursor):
    def __init__(self, cursor: sqlite3.Cursor):
        self._cursor = cursor

    @java_method_def('getCount', '()I')
    def getCount(self, emu):
        return self._cursor.rowcount

    @java_method_def('close', '()V')
    def close(self, emu):
        self._cursor.close()


class SQLiteDatabase(metaclass=JavaClassDef, jvm_name='android/database/sqlite/SQLiteDatabase',
                     jvm_fields=[
                         JavaFieldDef('OPEN_READWRITE', 'I', True, OPEN_READWRITE),
                         JavaFieldDef('OPEN_READONLY', 'I', True, OPEN_READONLY),
                     ]):
    def __init__(self, emu, path: str, flags: int, cursor_factory: SQLiteDatabase_CursorFactory):
        self._path = path
        self._flags = flags
        self._cursor_factory = cursor_factory

        if self._cursor_factory is not None:
            raise NotImplementedError()

        # TODO: Take flags into account
        self._db = sqlite3.connect(emu.vfs.translate_path(path))

    @staticmethod
    @java_method_def('openDatabase',
                     '(Ljava/lang/String;Landroid/database/sqlite/SQLiteDatabase$CursorFactory;I)Landroid/database/sqlite/SQLiteDatabase;',
                     args_list=['jstring', 'jobject', 'jint'])
    def openDatabase(emu, path: String, cursor_factory: SQLiteDatabase_CursorFactory, flags: int):
        return SQLiteDatabase(emu, path.get_py_string(), flags, cursor_factory)

    @java_method_def('rawQuery', '(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;', args_list=['jstring', 'jobject'])
    def rawQuery(self, emu, sql: String, selection_args: StringArray):
        sql = sql.get_py_string()

        if selection_args:
            selection_args = selection_args.get_py_items()
        else:
            selection_args = []

        logger.debug('Executing query: %s. Args: %s', sql, selection_args)

        return SQLiteCursor(self._db.execute(sql, selection_args))

    @java_method_def('close', '()V')
    def close(self, emu):
        self._db.close()
