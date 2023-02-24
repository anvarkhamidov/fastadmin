from enum import Enum

from pydantic import BaseModel


class WidgetType(str, Enum):
    Input = "Input"
    InputNumber = "InputNumber"
    TextArea = "TextArea"
    Select = "Select"
    AsyncSelect = "AsyncSelect"
    Switch = "Switch"
    Checkbox = "Checkbox"
    TimePicker = "TimePicker"
    DatePicker = "DatePicker"
    DateTimePicker = "DateTimePicker"
    RangePicker = "RangePicker"
    RadioGroup = "RadioGroup"
    CheckboxGroup = "CheckboxGroup"
    Upload = "Upload"


class ModelPermission(str, Enum):
    Add = "Add"
    Change = "Change"
    Delete = "Delete"
    Export = "Export"


class ListConfigurationFieldSchema(BaseModel):
    sorter: bool | None
    width: int | None
    is_link: bool | None
    empty_value_display: str
    filter_widget_type: WidgetType | None
    filter_widget_props: dict | None
    filter_condition: str | None


class AddConfigurationFieldSchema(BaseModel):
    form_widget_type: WidgetType
    form_widget_props: dict | None
    required: bool | None


class ChangeConfigurationFieldSchema(BaseModel):
    form_widget_type: WidgetType
    form_widget_props: dict | None
    required: bool | None


class ModelFieldSchema(BaseModel):
    name: str
    list_configuration: ListConfigurationFieldSchema | None
    add_configuration: AddConfigurationFieldSchema | None
    change_configuration: ChangeConfigurationFieldSchema | None


class ModelSchema(BaseModel):
    name: str
    permissions: list[ModelPermission]
    fields: list[ModelFieldSchema]
    list_per_page: int | None
    save_on_top: bool | None
    search_help_text: str | None


class ConfigurationSchema(BaseModel):
    site_name: str
    site_sign_in_logo: str
    site_header_logo: str
    site_favicon: str
    primary_color: str
    models: list[ModelSchema]