#include "cheatcodedisassembler.h"
#include <optional>
#include <QMessageBox>

#include "./action_replay_code.h"

namespace {
   static QString format_hex_8(std::uint8_t v) {
      return QString("0x%1").arg(QString::number(v, 16).toUpper(), 2, '0');;
   }
   static QString format_hex_16(std::uint16_t v) {
      return QString("0x%1").arg(QString::number(v, 16).toUpper(), 4, '0');;
   }
   static QString format_hex_32(std::uint32_t v) {
      return QString("0x%1").arg(QString::number(v, 16).toUpper(), 8, '0');;
   }

   std::uint32_t hex_00z0zzzz_to_0z00zzzz(std::uint32_t v) {
      std::uint32_t address = 0;
      address |= ((v >> 0x14) & 0xF) << 0x18;
      address |= (v & 0xFFFF);
      return address;
   }
}

cheatcodedisassembler::cheatcodedisassembler(QWidget *parent) : QMainWindow(parent) {
   ui.setupUi(this);

   QObject::connect(this->ui.button_disassemble, &QPushButton::clicked, this, [this]() {
      QString output;
      QString decrypted;

      enum class special_operand {
         end,
         slowdown = 4,
         button_1 = 8,
         button_2,
         button_4,
         patch_1 = 12,
         patch_2,
         patch_3,
         patch_4,
         endif = 20,
         else_branch = 48,
         fill_1 = 64,
         fill_2,
         fill_4,
      };

      auto lines = this->ui.textbox_encrypted->toPlainText().split('\n');

      struct pending_code {
         special_operand type;
         uint32_t prior_operand = 0;
      };
      std::optional<pending_code> prev;

      for (auto& line : lines) {
         line = line.trimmed();
         if (line.isEmpty())
            continue;

         QString hex;
         for (auto ch : line) {
            char charcode = ch.unicode();
            if (charcode >= '0' && charcode <= '9') {
               hex += ch;
               continue;
            }
            if (charcode >= 'a' && charcode <= 'z') {
               hex += ch;
               continue;
            }
            if (charcode >= 'A' && charcode <= 'Z') {
               hex += ch;
               continue;
            }
         }
         if (hex.size() < 16) {
            QMessageBox::critical(this, "Error", QString("Invalid code: ") + line);
            return;
         }

         action_replay_code ar;
         ar.opcode  = hex.left(8).toUInt(nullptr, 16);
         ar.operand = hex.right(8).toUInt(nullptr, 16);
         ar.decrypt();

         // For now, just emit the decrypted code.
         decrypted += format_hex_32(ar.opcode);
         decrypted += ' ';
         decrypted += format_hex_32(ar.operand);
         decrypted += '\n';

         if (prev.has_value()) {
            auto pending = prev.value();
            prev = {};

            switch (pending.type) {
               case special_operand::button_1:
               case special_operand::button_2:
               case special_operand::button_4:
                  output += "WHEN AR BUTTON PRESSED, WRITE ";
                  {
                     std::uint32_t address = hex_00z0zzzz_to_0z00zzzz(pending.prior_operand);

                     switch (pending.type) {
                        case special_operand::button_1: output += format_hex_8(ar.opcode); break;
                        case special_operand::button_2: output += format_hex_16(ar.opcode); break;
                        case special_operand::button_4: output += format_hex_32(ar.opcode); break;
                     }

                     output += " TO ";
                     output += format_hex_32(address);
                  }
                  break;
               case special_operand::patch_1:
               case special_operand::patch_2:
               case special_operand::patch_3:
               case special_operand::patch_4:
                  output += "WRITE ";
                  {
                     std::uint32_t address = 0;
                     address |= ((pending.prior_operand >> 0x14) & 0xF) << 0x18;
                     address |= (pending.prior_operand & 0xFFFF);
                     address += 0x08000000;

                     output += format_hex_16(ar.opcode);

                     output += " TO ";
                     output += format_hex_32(address);
                     output += " // writing to ROM";
                  }
                  break;
               case special_operand::fill_1:
               case special_operand::fill_2:
               case special_operand::fill_4:
                  {
                     std::uint8_t  iteration_count   = (ar.operand >> 16) & 0xFF;
                     std::uint8_t  increment_value   = ar.operand >> 24;
                     std::uint16_t increment_address = ar.operand & 0xFF;

                     QString base_value;
                     switch (pending.type) {
                        case special_operand::fill_1: base_value = format_hex_8(ar.operand); break;
                        case special_operand::fill_2: base_value = format_hex_16(ar.operand); break;
                        case special_operand::fill_4: base_value = format_hex_32(ar.operand); break;
                     }

                     std::uint32_t base_address = hex_00z0zzzz_to_0z00zzzz(pending.prior_operand);

                     output += "FOR i = 0 TO ";
                     output += format_hex_8(iteration_count);
                     output += ", DO:\n";

                     output += "   WRITE (";
                     output += base_value;
                     output += " + (i * ";
                     output += format_hex_8(increment_value);
                     output += ")) TO (";
                     output += format_hex_32(base_address);
                     output += " + (i * ";
                     output += format_hex_16(increment_address);
                     output += "))\n";
                  }
                  break;
            }

            output += '\n';
            continue;
         }

         if (ar.operand == 0x001DC0DE) {
            output += "AUTODETECT SIGNATURE ";
            output += format_hex_32(ar.opcode);
            output += '\n';
            continue;
         }
         if ((ar.opcode >> 0x18) == 0xC4) {
            output += "MASTERHOOK ";
            output += QString("08%1").arg(QString::number(ar.opcode & 0x00FFFFFF, 16).toUpper(), 6, '0');
            output += ' ';
            if ((ar.operand & 0x00000F00) == 1) {
               output += "SWITCH_OFF_ONLY ";
            }

            auto batch_size = (ar.operand >> 8) & 0xF;
            output += "BATCH=";
            output += QString::number(batch_size);
            output += ' ';

            auto hook_type = ar.operand & 0xF;
            output += "HOOK ON ";
            switch (hook_type) {
               case 0:
                  output += "BL";
                  break;
               case 1:
                  output += "PUSH LR THEN BL";
                  break;
               default:
                  output += "UNKNOWN(";
                  output += QString::number(hook_type);
                  output += ")";
                  break;
            }
            output += '\n';
            continue;
         }

         std::uint8_t condition     = (ar.opcode >> 0x1B) & 7; // none, equal, not equal, signed less, signed greater, unsigned less, unsigned greater, bitwise AND
         std::uint8_t operand_width = (ar.opcode >> 0x18) & 6; // 1, 2, or 4, when valid
         if (operand_width == 0 && ar.opcode != 0)
            operand_width = 1;

         if (condition) {
            std::uint8_t branch_action = (ar.opcode >> 0x1E) & 3; // affects next; affects next two; affects until end; disable

            output += "IF ";
            switch (operand_width) {
               case 1: output += format_hex_8(ar.operand); break;
               case 2: output += format_hex_16(ar.operand); break;
               case 4: output += format_hex_32(ar.operand); break;
            }
            output += ' ';
            switch (condition) {
               case 1: output += "=="; break;
               case 2: output += "!="; break;
               case 3: output += "> "; break;
               case 4: output += "< "; break;
               case 5: output += "> "; break;
               case 6: output += "< "; break;
               case 7: output += "& "; break;
            }
            output += ' ';

            std::uint32_t address = hex_00z0zzzz_to_0z00zzzz(ar.opcode);

            output += "*(";
            switch (condition) {
               case 3:
               case 4:
                  break;
               default:
                  output += 'u';
                  break;
            }
            switch (operand_width) {
               case 1: output += "int8_t";  break;
               case 2: output += "int16_t"; break;
               case 4: output += "int32_t"; break;
            }
            output += "*)";
            output += format_hex_32(address);

            output += " THEN ";
            switch (branch_action) {
               case 0: output += "RUN NEXT 1 LINES"; break;
               case 1: output += "RUN NEXT 2 LINES"; break;
               case 2: output += "RUN UNTIL END"; break;
               case 3: output += "DISABLE"; break;
            }

            output += '\n';
            continue;
         }

         if (ar.opcode == 0) {
            auto special_code = (special_operand)((ar.operand >> 0x19) & 0x7F);
            switch (special_code) {
               case special_operand::end:
                  output += "END";
                  break;
               case special_operand::slowdown:
                  output += "SLOWDOWN WITH ";
                  {
                     std::uint8_t spins = (ar.operand >> 8) & 0xFF;
                     output += QString::number(spins);
                  }
                  output += " LOOPS PER CODE CYCLE";
                  break;
               case special_operand::button_1:
               case special_operand::button_2:
               case special_operand::button_4:
               case special_operand::patch_1:
               case special_operand::patch_2:
               case special_operand::patch_3:
               case special_operand::patch_4:
               case special_operand::fill_1:
               case special_operand::fill_2:
               case special_operand::fill_4:
                  prev = {
                     .type          = special_code,
                     .prior_operand = ar.operand,
                  };
                  continue;
               case special_operand::endif:
                  output += "ENDIF";
                  break;
               case special_operand::else_branch:
                  output += "ELSE";
                  break;
            }
            output += '\n';
            continue;
         }

         std::uint8_t action = (ar.opcode >> 0x1E);
         if (action == 0 || action == 1) {
            std::uint32_t address = hex_00z0zzzz_to_0z00zzzz(ar.opcode);

            uint32_t modifier = 0;
            if (operand_width == 1)
               modifier = ar.operand >> 8;
            else if (operand_width == 2)
               modifier = (ar.operand >> 16) * 2;

            QString value_to_write;
            switch (operand_width) {
               case 1: value_to_write = format_hex_8(ar.operand); break;
               case 2: value_to_write = format_hex_16(ar.operand); break;
               case 4: value_to_write = format_hex_32(ar.operand); break;
            }

            if (action == 0) {
               if (modifier) {
                  output += "FILL WITH ";
                  output += value_to_write;
                  output += "FROM ";
                  output += format_hex_32(address);
                  output += " TO ";
                  output += format_hex_32(address + modifier);
               } else {
                  output += "WRITE ";
                  output += value_to_write;
                  output += " TO ";
                  output += format_hex_32(address);
               }
            } else {
               output += "WRITE ";
               output += value_to_write;
               output += " TO ";
               output += format_hex_32(address + modifier);
            }
         } else if (action == 2) {
            std::uint32_t address = hex_00z0zzzz_to_0z00zzzz(ar.opcode);

            QString value_to_write;
            switch (operand_width) {
               case 1: value_to_write = QString("0x%1").arg(QString::number(ar.operand & 0x00FF, 16).toUpper(), 2, '0'); break;
               case 2: value_to_write = QString("0x%1").arg(QString::number(ar.operand & 0xFFFF, 16).toUpper(), 4, '0'); break;
               case 4: value_to_write = QString("0x%1").arg(QString::number(ar.operand,          16).toUpper(), 8, '0'); break;
            }

            output += "ADD ";
            output += value_to_write;
            output += " TO VALUE AT ";
            output += format_hex_32(address);
         } else if (action == 3) {
            operand_width = ((ar.opcode >> 24) & 1) + 1;

            std::uint32_t address = 0x04000000;
            address |= (ar.opcode & 0xFFFF);

            QString value_to_write;
            switch (operand_width) {
               case 1: value_to_write = QString("0x%1").arg(QString::number(ar.operand & 0x00FF, 16).toUpper(), 2, '0'); break;
               case 2: value_to_write = QString("0x%1").arg(QString::number(ar.operand & 0xFFFF, 16).toUpper(), 4, '0'); break;
               case 4: value_to_write = QString("0x%1").arg(QString::number(ar.operand, 16).toUpper(), 8, '0'); break;
            }

            output += "WRITE ";
            output += value_to_write;
            output += " TO ";
            output += format_hex_32(address);
            output += " // IO register write";
         }
         output += '\n';
         continue;
      }

      output += "\n/* decrypted:\n";
      output += decrypted;
      output += "\n*/";

      this->ui.textbox_disassembled->setPlainText(output);
   });
}

cheatcodedisassembler::~cheatcodedisassembler() {
}
