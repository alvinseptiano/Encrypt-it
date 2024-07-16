#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(rustdoc::missing_crate_level_docs)]

mod crypto;
mod themes;

use std::{result, thread};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};
use egui::{Spinner, Ui};
use eframe::egui::{self, Style, Visuals, ViewportCommand};
use human_duration::human_duration;
use crate::crypto::Crypto;

fn main() -> eframe::Result {
    env_logger::init();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_decorations(false)
            .with_inner_size([800.0, 600.0])
            .with_min_inner_size([400.0, 100.0])
            .with_drag_and_drop(true)
            .with_transparent(true),

        ..Default::default()
    };

    eframe::run_native(
        "ChaCha20-Poly1305",
        options,
        Box::new(|creation_context| {
            let style = Style {
                visuals: Visuals::light(),
                ..Style::default()
            };
            creation_context.egui_ctx.set_style(style);
            Ok(Box::new(MyApp::new()))
        }),
    )
}

#[derive(PartialEq, Clone, Copy)]
enum EncryptType {
    Encryption,
    Decryption
}

impl Default for EncryptType {
    fn default() -> Self {
        EncryptType::Encryption
    }
}

#[derive(Default)]
struct MyApp {
    dropped_files: Vec<egui::DroppedFile>,
    picked_path: Option<String>,
    password: String,
    selected_option: EncryptType,
    file_path: String,
    output_message: Arc<Mutex<String>>,
    is_processing: bool,
    tx: Option<Sender<String>>, // Add sender
    rx: Option<Receiver<String>>, // Add receiver
}

impl eframe::App for MyApp {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        egui::Rgba::TRANSPARENT.to_array() // Make sure we don't paint anything behind the rounded corners
    }
    
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        custom_window_frame(ctx, "ChaCha20-Poly1305", |ui| {
            ctx.set_pixels_per_point(2.0);
            ui.group(|ui| {
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.label("File: ");
                    if ui.button("Buka File atau Drag kesini").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.picked_path = Some(path.display().to_string());        
                        }
                    } 
                    if !self.dropped_files.is_empty() {
                        ui.group(|ui| {
                            ui.label("Dropped files:");
        
                            for file in &self.dropped_files {
                                let mut info = if let Some(path) = &file.path {
                                    path.display().to_string()
                                } else if !file.name.is_empty() {
                                    file.name.clone()
                                } else {
                                    "???".to_owned()
                                };
        
                                let mut additional_info = vec![];
                                if !file.mime.is_empty() {
                                    additional_info.push(format!("type: {}", file.mime));
                                }
                                if let Some(bytes) = &file.bytes {
                                    additional_info.push(format!("{} bytes", bytes.len()));
                                }
                                if !additional_info.is_empty() {
                                    info += &format!(" ({})", additional_info.join(", "));
                                }
        
                                ui.label(info);
                            }
                        });
                    }
                });

                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.label("Jenis operasi: ");
                    ui.radio_value(
                        &mut self.selected_option, EncryptType::Encryption,"Enkripsi");
                    ui.radio_value(
                        &mut self.selected_option, EncryptType::Decryption, "Dekripsi");
                });
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    let name_label = ui.label("Kata sandi: ");
                    ui.text_edit_singleline(&mut self.password)
                    .labelled_by(name_label.id);
                });
                ui.add_space(10.0);

                if ui.button("Proses File").clicked() {
                    self.update_output_message("Proses sedang berlangsung..");
                    ui.add(egui::Spinner::new()); 
                    self.encrypt();
                    ctx.request_repaint();
                }
            }); // Group end
                
            ui.separator();
            self.show_label(ui);
        });
        preview_files_being_dropped(ctx);
        ctx.input(|i| { // Collect dropped files:
            if !i.raw.dropped_files.is_empty() {
                self.dropped_files.clone_from(&i.raw.dropped_files);
            }
        });

        if let Some(rx) = &self.rx {
            if let Ok(message) = rx.try_recv() {
                self.update_output_message(&message);
                self.is_processing = false;
            }
        }

        if self.is_processing {
            ctx.request_repaint(); // Request repaint to update the UI
        }
    }
    
}

impl MyApp {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            tx: Some(tx),
            rx: Some(rx),
            ..Default::default()
        }
    }
    fn show_label(&self, ui: &mut Ui) {
        let output_message = self.output_message.lock().unwrap();
        if self.is_processing {
            ui.horizontal(|ui| {
                ui.label("Proses sedang berlangsung..");
                ui.add(Spinner::new()); 
            });
        } else {
            ui.label(format!("Output: {}", &*output_message));
        }
    }
    fn update_output_message(&self, new_text: &str) {
        let mut output_message = self.output_message.lock().unwrap();
        *output_message = new_text.to_string();
    }
    fn encrypt(&mut self) {
        println!("encrypt");
        self.is_processing = true;
        let file_path = self.file_path.clone();
        let password = self.password.clone();
        let selected_option = self.selected_option;
        let tx = self.tx.clone().unwrap();

        thread::spawn(move || {
            let mut key = password.as_bytes().to_vec();
            key.resize(32, 0);
            let mut nonce = password.as_bytes().to_vec();
            nonce.resize(24, 0);
        
            let key_array: [u8; 32] = key.try_into().expect("The string could not be converted into a [u8; 32] array");
            let nonce_array: [u8; 24] = nonce.try_into().expect("The string could not be converted into a [u8; 24] array");

            let start = Instant::now();
            let duration: Duration;
            println!("{}", file_path);
            let result_message = match selected_option {
                EncryptType::Encryption => 
                match Crypto::encrypt(&file_path, &key_array, &nonce_array) {
                    Ok(_) => {
                        duration = start.elapsed();
                        format!("Enkripsi berhasil dalam waktu {}", human_duration(&duration))
                    },
                    Err(_e) => "Enkripsi gagal!".to_string(),
                },
                EncryptType::Decryption => 
                match Crypto::decrypt(&file_path, &key_array, &nonce_array) {
                    Ok(_) => {
                        duration = start.elapsed();
                        format!("Dekripsi berhasil dalam waktu {}", human_duration(&duration))
                    },
                    Err(_e) => "Dekripsi gagal!".to_string(),
                },
            };
            println!("{}", result_message);
            tx.send(result_message).unwrap();
        });
    }
}

fn preview_files_being_dropped(ctx: &egui::Context) {
    use egui::*;
    use std::fmt::Write as _;

    if !ctx.input(|i| i.raw.hovered_files.is_empty()) {
        let text = ctx.input(|i| {
            let mut text = "Dropping files:\n".to_owned();
            for file in &i.raw.hovered_files {
                if let Some(path) = &file.path {
                    write!(text, "\n{}", path.display()).ok();
                } else if !file.mime.is_empty() {
                    write!(text, "\n{}", file.mime).ok();
                } else {
                    text += "\n???";
                }
            }
            text
        });

        let painter =
            ctx.layer_painter(LayerId::new(Order::Foreground, Id::new("file_drop_target")));

        let screen_rect = ctx.screen_rect();
        painter.rect_filled(screen_rect, 0.0, Color32::from_black_alpha(192));
        painter.text(
            screen_rect.center(),
            Align2::CENTER_CENTER,
            text,
            TextStyle::Heading.resolve(&ctx.style()),
            Color32::WHITE,
        );
    }
}

fn custom_window_frame(ctx: &egui::Context, title: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    use egui::*;
    
    let panel_frame = egui::Frame {
        fill: ctx.style().visuals.window_fill(),
        rounding: 10.0.into(),
        stroke: ctx.style().visuals.widgets.noninteractive.fg_stroke,
        outer_margin: 0.5.into(), // so the stroke is within the bounds
        ..Default::default()
    };

    CentralPanel::default().frame(panel_frame).show(ctx, |ui| {
        let app_rect = ui.max_rect();

        let title_bar_height = 32.0;
        let title_bar_rect = {
            let mut rect = app_rect;
            rect.max.y = rect.min.y + title_bar_height;
            rect
        };
        title_bar_ui(ui, title_bar_rect, title);

        // Add the contents:
        let content_rect = {
            let mut rect = app_rect;
            rect.min.y = title_bar_rect.max.y;
            rect
        }
        .shrink(4.0);
        let mut content_ui = ui.child_ui(content_rect, *ui.layout(), None);
        add_contents(&mut content_ui);

        themes::catppuccin::set_theme(&ctx, themes::catppuccin::LATTE);
    });
}

fn title_bar_ui(ui: &mut egui::Ui, title_bar_rect: eframe::epaint::Rect, title: &str) {
    use egui::*;

    let painter = ui.painter();

    let title_bar_response = ui.interact(
        title_bar_rect,
        Id::new("title_bar"),
        Sense::click_and_drag(),
    );

    // Paint the title:
    painter.text(
        title_bar_rect.center(),
        Align2::CENTER_CENTER,
        title,
        FontId::proportional(20.0),
        ui.style().visuals.text_color(),
    );

    // Paint the line under the title:
    painter.line_segment(
        [
            title_bar_rect.left_bottom() + vec2(1.0, 0.0),
            title_bar_rect.right_bottom() + vec2(-1.0, 0.0),
        ],
        ui.visuals().widgets.noninteractive.bg_stroke,
    );

    // Interact with the title bar (drag to move window):
    if title_bar_response.double_clicked() {
        let is_maximized = ui.input(|i| i.viewport().maximized.unwrap_or(false));
        ui.ctx()
            .send_viewport_cmd(ViewportCommand::Maximized(!is_maximized));
    }

    if title_bar_response.drag_started_by(PointerButton::Primary) {
        ui.ctx().send_viewport_cmd(ViewportCommand::StartDrag);
    }

    ui.allocate_ui_at_rect(title_bar_rect, |ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            ui.visuals_mut().button_frame = false;
            ui.add_space(8.0);
            close_maximize_minimize(ui);
        });
    });
}

fn close_maximize_minimize(ui: &mut egui::Ui) {
    use egui::{Button, RichText};

    let button_height = 12.0;

    let close_response = ui
        .add(Button::new(RichText::new("❌").size(button_height)))
        .on_hover_text("Close the window");
    if close_response.clicked() {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
    }

    let is_maximized = ui.input(|i| i.viewport().maximized.unwrap_or(false));
    if is_maximized {
        let maximized_response = ui
            .add(Button::new(RichText::new("🗗").size(button_height)))
            .on_hover_text("Restore window");
        if maximized_response.clicked() {
            ui.ctx()
                .send_viewport_cmd(ViewportCommand::Maximized(false));
        }
    } else {
        let maximized_response = ui
            .add(Button::new(RichText::new("🗗").size(button_height)))
            .on_hover_text("Maximize window");
        if maximized_response.clicked() {
            ui.ctx().send_viewport_cmd(ViewportCommand::Maximized(true));
        }
    }

    let minimized_response = ui
        .add(Button::new(RichText::new("🗕").size(button_height)))
        .on_hover_text("Minimize the window");
    if minimized_response.clicked() {
        ui.ctx().send_viewport_cmd(ViewportCommand::Minimized(true));
    }
}

